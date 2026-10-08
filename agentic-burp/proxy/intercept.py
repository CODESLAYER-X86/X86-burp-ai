from __future__ import annotations
import asyncio
import uuid
import time
from typing import Dict, List, Optional, Tuple, Any
from models.request import HTTPRequest
from models.response import HTTPResponse
from .history import InterceptedTransaction
from .modification import ModificationDiffer


class InterceptManager:
    """
    Manages browser interception queue, original vs modified diffs,
    and interception modes (Pass-through, Human, AI).
    """
    MODE_PASS_THROUGH = "PASS_THROUGH"
    MODE_HUMAN_INTERCEPT = "HUMAN_INTERCEPT"
    MODE_AI_INTERCEPT = "AI_INTERCEPT"

    AI_POLICY_OFF = "OFF"
    AI_POLICY_OBSERVE_ONLY = "OBSERVE_ONLY"
    AI_POLICY_ASK_BEFORE_MODIFY = "ASK_BEFORE_MODIFY"
    AI_POLICY_AUTO_MODIFY = "AUTO_MODIFY_WITHIN_SCOPE"

    def __init__(self):
        self.mode = self.MODE_PASS_THROUGH
        self.ai_policy = self.AI_POLICY_OBSERVE_ONLY
        self.intercept_queue: Dict[str, Tuple[InterceptedTransaction, asyncio.Event]] = {}
        self.history: List[InterceptedTransaction] = []

    def set_mode(self, mode: str):
        self.mode = mode

    def set_ai_policy(self, policy: str):
        self.ai_policy = policy

    async def handle_request(self, original_req: HTTPRequest) -> Tuple[str, HTTPRequest]:
        """
        Processes incoming request from browser proxy.
        Returns ("FORWARD", final_request) or ("DROP", None).
        """
        tx_id = f"tx_{uuid.uuid4().hex[:8]}"
        tx = InterceptedTransaction(
            id=tx_id,
            timestamp=time.time(),
            original_request=original_req,
            modified_request=HTTPRequest.model_validate(original_req.to_dict()),
            status="PENDING",
            intercepted_by="pass_through" if self.mode == self.MODE_PASS_THROUGH else "human"
        )

        # Mode A: Pass-Through
        if self.mode == self.MODE_PASS_THROUGH:
            tx.status = "FORWARDED"
            self.history.append(tx)
            return "FORWARD", original_req

        # Mode B: Human Interception (hold in queue)
        event = asyncio.Event()
        self.intercept_queue[tx_id] = (tx, event)

        try:
            # Wait until human or AI acts, or 60s timeout
            await asyncio.wait_for(event.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            tx.status = "FORWARDED"
            self.intercept_queue.pop(tx_id, None)
            self.history.append(tx)
            return "FORWARD", original_req

        self.intercept_queue.pop(tx_id, None)
        self.history.append(tx)

        if tx.status == "DROPPED":
            return "DROP", original_req

        final_req = tx.modified_request or tx.original_request
        return "FORWARD", final_req

    def forward_intercepted(self, tx_id: str, modified_req: Optional[HTTPRequest] = None, reason: str = ""):
        entry = self.intercept_queue.get(tx_id)
        if not entry:
            return False

        tx, event = entry
        if modified_req:
            diffs = ModificationDiffer.compute_diff(tx.original_request, modified_req, reason)
            tx.modified_request = modified_req
            tx.modifications = diffs

        tx.status = "FORWARDED"
        event.set()
        return True

    def drop_intercepted(self, tx_id: str):
        entry = self.intercept_queue.get(tx_id)
        if not entry:
            return False

        tx, event = entry
        tx.status = "DROPPED"
        event.set()
        return True

    def get_pending_queue(self) -> List[Dict[str, Any]]:
        return [tx.to_dict() for tx, _ in self.intercept_queue.values()]

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [tx.to_dict() for tx in self.history[-limit:]]
