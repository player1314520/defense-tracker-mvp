# -*- coding: utf-8 -*-
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import pytest

from v9.errors import PermissionDenied
from v9.publication import apply_document_changes, build_document_docx, new_document


def _service(tmp_path):
    from v9.service import V9Service

    service = V9Service(tmp_path / "v9.sqlite3", tmp_path / ".master")
    owner = service.get_or_create_personal_context()
    return service, owner


def _evidence(service, context, suffix="1"):
    return service.archive_news_evidence(
        context,
        {
            "aid": f"p5-evidence-{suffix}",
            "title": f"公开来源证据 {suffix}",
            "summary": "可追溯原文摘要",
            "source": "Source A",
            "link": f"https://example.test/p5-{suffix}",
            "date": datetime.now(timezone.utc).isoformat(),
            "priority": {"stars": 8},
        },
    )


def _valid_document(service, context):
    evidence = _evidence(service, context)
    created = service.create_document(
        context,
        {
            "kind": "report",
            "title": "印太态势专题报告",
            "paragraphs": [
                {
                    "heading": "核心判断",
                    "text": "公开材料显示相关活动节奏出现变化。",
                    "evidence_ids": [evidence["record_id"]],
                    "source_status": "source_claim",
                    "fact_check": "passed",
                }
            ],
        },
    )
    return service.list_documents(context)[0], evidence


def _member_context(service, owner, role):
    user_id = f"{role}-user"
    service.add_member(
        owner["organization_id"], owner["user_id"], user_id, role
    )
    device = service.add_device(
        owner["organization_id"], owner["user_id"], user_id, f"{role}-desktop"
    )
    return {
        "organization_id": owner["organization_id"],
        "user_id": user_id,
        "device_id": device["device_id"],
    }


def test_visible_document_editor_disables_the_generic_brief_kind():
    html = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text(
        encoding="utf-8"
    )

    assert '<option value="brief" disabled>要讯（使用下方专用流程）</option>' in html


def test_document_requires_cited_fact_checked_paragraphs_before_approval(tmp_path):
    service, owner = _service(tmp_path)
    evidence = _evidence(service, owner)
    created = service.create_document(
        owner,
        {
            "kind": "brief",
            "title": "待核查要讯",
            "paragraphs": [
                {
                    "heading": "判断",
                    "text": "尚未通过事实核查。",
                    "evidence_ids": [evidence["record_id"]],
                    "source_status": "source_claim",
                    "fact_check": "pending",
                }
            ],
        },
    )
    document = service.list_documents(owner)[0]
    assert document["content"]["validation"]["ready"] is False
    assert "事实核查" in document["content"]["validation"]["errors"][0]

    item = service.create_publication_item(owner, created["record_id"])
    board_item = service.list_publication_items(owner)[0]
    assert board_item["content"]["status"] == "evidence_needed"
    with pytest.raises(ValueError, match="校验"):
        service.move_publication_item(
            owner,
            item["record_id"],
            expected_version=item["version"],
            status="pending_approval",
        )


def test_v9_generic_document_cannot_release_or_export_unvalidated_brief_text():
    content = new_document(
        {
            "kind": "brief",
            "title": "测试要讯",
            "paragraphs": [
                {
                    "heading": "正文",
                    "text": "事件时间：近期。有关单位开展行动。",
                    "evidence_ids": ["evidence-1"],
                    "source_status": "verified",
                    "fact_check": "passed",
                }
            ],
        }
    )

    assert content["validation"]["ready"] is False
    assert any("要讯专用" in error for error in content["validation"]["errors"])
    with pytest.raises(ValueError, match="禁止生成DOCX"):
        build_document_docx(content, [])


def test_v9_export_rechecks_validation_before_building_files(monkeypatch):
    from v9.service import V9Service

    content = new_document(
        {
            "kind": "brief",
            "title": "测试要讯",
            "paragraphs": [
                {
                    "text": "事件时间：近期。有关单位开展行动。",
                    "evidence_ids": ["evidence-1"],
                    "source_status": "verified",
                    "fact_check": "passed",
                }
            ],
        }
    )
    service = object.__new__(V9Service)
    monkeypatch.setattr(
        service,
        "_record_with_hash",
        lambda *_args, **_kwargs: {"content": content},
    )

    with pytest.raises(ValueError, match="禁止导出"):
        service.export_document({}, "document-1", "docx")


def test_forged_stored_validation_cannot_bypass_release_gate(tmp_path):
    service, owner = _service(tmp_path)
    forged = service.create_record(
        owner["organization_id"],
        owner["user_id"],
        owner["device_id"],
        "document",
        {
            "kind": "report",
            "title": "伪造校验状态",
            "paragraphs": [],
            "validation": {"ready": True, "errors": []},
        },
    )
    item = service.create_publication_item(owner, forged["record_id"])
    current = service.list_publication_items(owner)[0]

    assert current["content"]["status"] == "evidence_needed"
    with pytest.raises(ValueError, match="校验"):
        service.move_publication_item(
            owner,
            item["record_id"],
            expected_version=item["version"],
            status="pending_approval",
        )


def test_editor_cannot_sign_and_approver_cannot_edit_document(tmp_path):
    service, owner = _service(tmp_path)
    document, _ = _valid_document(service, owner)
    item = service.create_publication_item(owner, document["record_id"])
    item = service.move_publication_item(
        owner,
        item["record_id"],
        expected_version=item["version"],
        status="pending_approval",
    )
    editor = _member_context(service, owner, "editor")
    approver = _member_context(service, owner, "approver")

    with pytest.raises(PermissionDenied):
        service.sign_publication_item(
            editor, item["record_id"], expected_version=item["version"]
        )
    with pytest.raises(PermissionDenied):
        service.update_document(
            approver,
            document["record_id"],
            expected_version=document["version"],
            changes={"title": "越权修改"},
        )

    signed = service.sign_publication_item(
        approver, item["record_id"], expected_version=item["version"]
    )
    assert signed["status"] == "signed"


def test_signed_snapshot_is_immutable_and_recall_preserves_receipt(tmp_path):
    service, owner = _service(tmp_path)
    document, _ = _valid_document(service, owner)
    item = service.create_publication_item(owner, document["record_id"])
    item = service.move_publication_item(
        owner,
        item["record_id"],
        expected_version=item["version"],
        status="pending_approval",
    )
    signed = service.sign_publication_item(
        owner, item["record_id"], expected_version=item["version"]
    )
    signed_record = service.list_publication_items(owner)[0]
    receipt = signed_record["content"]["signed_snapshot"]["receipt"]
    assert receipt["document_version"] == document["version"]
    assert receipt["document_content_hash"] == document["content_hash"]

    with pytest.raises(PermissionDenied, match="已签发"):
        service.update_record(
            owner["organization_id"],
            owner["user_id"],
            owner["device_id"],
            item["record_id"],
            expected_version=signed["version"],
            content={"status": "editing"},
        )

    recalled = service.recall_publication_item(
        owner,
        item["record_id"],
        expected_version=signed["version"],
        reason="来源状态需要重新确认",
    )
    recalled_record = service.list_publication_items(owner)[0]
    assert recalled["status"] == "recalled"
    assert recalled_record["content"]["signed_snapshot"]["receipt"] == receipt


def test_writer_frontend_round_trips_claim_links_and_all_epistemic_states():
    source = (
        Path("static/js/p5-publication-v9.js")
        .read_text(encoding="utf-8")
    )

    assert "scenario_assumption: '情景假设'" in source
    assert "claim_ids: []" in source
    assert 'data-paragraph-field="claims"' in source
    assert (
        "claim_ids: csv(card.querySelector("
        "'[data-paragraph-field=\"claims\"]'"
    ) in source


def test_paragraph_normalization_preserves_claim_links_across_revisions():
    document = new_document(
        {
            "kind": "report",
            "title": "引用闭环",
            "paragraphs": [
                {
                    "paragraph_id": "paragraph-1",
                    "heading": "判断",
                    "text": "正文",
                    "evidence_ids": ["evidence-1"],
                    "claim_ids": [" claim-1 ", "claim-1", "claim-2"],
                    "source_status": "source_claim",
                    "fact_check": "passed",
                }
            ],
        }
    )
    assert document["paragraphs"][0]["claim_ids"] == [
        "claim-1",
        "claim-2",
    ]

    revised = apply_document_changes(
        document,
        {
            "paragraphs": [
                {
                    **document["paragraphs"][0],
                    "text": "修订正文",
                }
            ]
        },
    )
    assert revised["paragraphs"][0]["paragraph_id"] == "paragraph-1"
    assert revised["paragraphs"][0]["claim_ids"] == [
        "claim-1",
        "claim-2",
    ]


def test_document_claim_links_must_reference_same_org_claim_records(tmp_path):
    service, owner = _service(tmp_path)
    evidence = _evidence(service, owner)
    claim = service.create_claim(
        owner,
        {
            "statement": "公开来源支持相关活动节奏发生变化",
            "epistemic_status": "source_claim",
            "evidence_ids": [evidence["record_id"]],
        },
    )
    paragraph = {
        "heading": "核心判断",
        "text": "相关活动节奏发生变化。",
        "evidence_ids": [evidence["record_id"]],
        "claim_ids": [evidence["record_id"]],
        "source_status": "source_claim",
        "fact_check": "passed",
    }

    with pytest.raises(ValueError, match="claim"):
        service.create_document(
            owner,
            {
                "kind": "report",
                "title": "错误主张引用",
                "paragraphs": [paragraph],
            },
        )

    created = service.create_document(
        owner,
        {
            "kind": "report",
            "title": "有效主张引用",
            "paragraphs": [
                {**paragraph, "claim_ids": [claim["record_id"]]}
            ],
        },
    )
    stored = service.list_documents(owner)[0]
    assert created["record_id"] == stored["record_id"]
    assert stored["content"]["paragraphs"][0]["claim_ids"] == [
        claim["record_id"]
    ]

    with pytest.raises(ValueError, match="claim"):
        service.update_document(
            owner,
            created["record_id"],
            expected_version=created["version"],
            changes={
                "paragraphs": [
                    {**paragraph, "claim_ids": [evidence["record_id"]]}
                ]
            },
        )


def test_document_revisions_and_exports_include_source_index(tmp_path):
    from docx import Document

    service, owner = _service(tmp_path)
    document, evidence = _valid_document(service, owner)
    updated = service.update_document(
        owner,
        document["record_id"],
        expected_version=document["version"],
        changes={
            "paragraphs": [
                {
                    "heading": "修订判断",
                    "text": "修订后的判断仍引用同一公开证据。",
                    "evidence_ids": [evidence["record_id"]],
                    "source_status": "source_claim",
                    "fact_check": "passed",
                }
            ],
            "revision_note": "主编修订",
        },
    )
    current = service.list_documents(owner)[0]
    assert updated["version"] == 2
    assert current["content"]["revision"] == 2
    assert current["content"]["revisions"][0]["paragraphs"][0]["heading"] == "核心判断"

    docx_bytes, docx_name = service.export_document(
        owner, document["record_id"], "docx"
    )
    parsed = Document(BytesIO(docx_bytes))
    text = "\n".join(p.text for p in parsed.paragraphs)
    assert "来源索引" in text
    assert "公开来源证据 1" in text
    assert evidence["record_id"] in text
    assert docx_name.endswith(".docx")

    pdf_bytes, pdf_name = service.export_document(
        owner, document["record_id"], "pdf"
    )
    assert pdf_bytes.startswith(b"%PDF")
    assert pdf_name.endswith(".pdf")


def test_audit_records_are_encrypted_and_cover_board_sign_recall(tmp_path):
    service, owner = _service(tmp_path)
    document, _ = _valid_document(service, owner)
    item = service.create_publication_item(owner, document["record_id"])
    item = service.move_publication_item(
        owner,
        item["record_id"],
        expected_version=item["version"],
        status="pending_approval",
    )
    signed = service.sign_publication_item(
        owner, item["record_id"], expected_version=item["version"]
    )
    service.recall_publication_item(
        owner,
        item["record_id"],
        expected_version=signed["version"],
        reason="复核",
    )

    actions = [
        row["content"]["action"] for row in service.list_audit_events(owner)
    ]
    assert actions == [
        "publication.created",
        "publication.moved",
        "publication.signed",
        "publication.recalled",
    ]
    raw = service.database_path.read_bytes()
    assert "来源状态需要重新确认".encode() not in raw
    assert "印太态势专题报告".encode() not in raw
