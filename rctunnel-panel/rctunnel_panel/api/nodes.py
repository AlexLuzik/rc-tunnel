"""Node CRUD + rctd.yml export (rctunnel-engine data-plane config)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import require_admin
from ..models import Node
from ..schemas import NodeCreate, NodeOut

router = APIRouter()


def render_rctd(node: Node) -> str:
    """Flat-YAML config for the node's rctd (RC-Tunnel data-plane server)."""
    s = get_settings()
    pki = s.pki_dir.rstrip("/")
    return (
        f"# RC-Tunnel data-plane server (rctd) config for node '{node.name}'\n"
        f'control: ":{node.control_port}"\n'
        f'work:    ":{s.rctd_workconn_port}"\n'
        f'vhost:   "127.0.0.1:{node.vhost_http_port}"\n'
        f'stats:   "127.0.0.1:7401"\n'
        f'token:   "{node.node_token}"\n'
        f'cert:    "{pki}/server.crt"\n'
        f'key:     "{pki}/server.key"\n'
        f'ca:      "{pki}/ca.crt"\n'
    )


@router.get("", response_model=list[NodeOut], dependencies=[Depends(require_admin)])
def list_nodes(db: Session = Depends(get_db)) -> list[Node]:
    return list(db.scalars(select(Node)))


@router.post("", response_model=NodeOut, dependencies=[Depends(require_admin)])
def create_node(body: NodeCreate, db: Session = Depends(get_db)) -> Node:
    if db.scalar(select(Node).where(Node.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "node name exists")
    node = Node(**body.model_dump())
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@router.get("/{node_id}/rctd.yml", dependencies=[Depends(require_admin)])
def export_rctd(node_id: int, db: Session = Depends(get_db)) -> Response:
    node = db.get(Node, node_id)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "node not found")
    return Response(render_rctd(node), media_type="text/yaml")
