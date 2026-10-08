"""受保护资源入口：按 read/write/manage 作用域控制，三类入口分别限流。"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import (
    documents_manage_rate_limit,
    documents_read_rate_limit,
    documents_write_rate_limit,
    require_scope,
)

router = APIRouter(prefix="/resources/documents", tags=["documents"])

# 本地内存中的示例资源
_DOCUMENTS: dict[int, dict] = {
    1: {"id": 1, "title": "公开手册", "body": "hello"},
    2: {"id": 2, "title": "内部纪要", "body": "secret"},
}


class DocumentIn(BaseModel):
    title: str
    body: str


@router.get("", dependencies=[Depends(documents_read_rate_limit)])
def list_documents(user: dict = Depends(require_scope("documents:read"))) -> list[dict]:
    return list(_DOCUMENTS.values())


@router.get("/{doc_id}", dependencies=[Depends(documents_read_rate_limit)])
def get_document(
    doc_id: int, user: dict = Depends(require_scope("documents:read"))
) -> dict:
    doc = _DOCUMENTS.get(doc_id)
    if doc is None:
        return {"error": "not_found"}
    return doc


@router.post(
    "",
    status_code=201,
    dependencies=[Depends(documents_write_rate_limit)],
)
def create_document(
    body: DocumentIn, user: dict = Depends(require_scope("documents:write"))
) -> dict:
    doc_id = max(_DOCUMENTS, default=0) + 1
    doc = {"id": doc_id, "title": body.title, "body": body.body}
    _DOCUMENTS[doc_id] = doc
    return doc


@router.delete(
    "/{doc_id}",
    dependencies=[Depends(documents_manage_rate_limit)],
)
def delete_document(
    doc_id: int, user: dict = Depends(require_scope("documents:manage"))
) -> dict:
    _DOCUMENTS.pop(doc_id, None)
    return {"detail": "deleted", "id": doc_id}
