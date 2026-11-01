"""Execute allowlisted evidence skills over evidence already collected by the browser.

No arbitrary Playwright, no form submission, no downloads, no request replay. The
only browser action allowed here is one explicit traversal to a same-registrable
login-like link discovered on the page.
"""
import re
from typing import Any, Iterable

from ..brand_guard import load_brands
from . import deterministic as det
from .envelopes import InvestigationFinding, Observation, SkillEnvelope
from .evidence import EvidenceStore

EVIDENCE_SKILLS = {
    "inspect-navigation",
    "inspect-page-content",
    "inspect-form-elements",
    "inspect-network-activity",
    "inspect-javascript-behavior",
    "inspect-embedded-content",
    "investigate-brand-impersonation",
    "investigate-form-destination",
    "investigate-redirect-chain",
    "investigate-external-domains",
}
MAX_SKILL_CALLS = 12
MAX_TEXT_EXCERPT = 6000


def _field_name(value: str) -> str:
    return str(value or "")[:80]


class EvidenceExecutor:
    def __init__(
        self,
        store: EvidenceStore,
        *,
        scan_id: str,
        user_id: str,
        url: str,
        browser_evidence: dict[str, Any],
        deterministic_findings: Iterable[Any],
    ):
        self.store = store
        self.scan_id = scan_id
        self.user_id = user_id
        self.url = url
        self.page_host = det.normalize_host(url)
        self.browser = dict(browser_evidence or {})
        self.deterministic_findings = list(deterministic_findings)
        self.calls = 0
        self.executed: list[str] = []
        self.traversals = 0
        self._traversed: set[str] = set()

    async def run(self, skill: str, params: dict[str, Any] | None = None) -> SkillEnvelope:
        if skill not in EVIDENCE_SKILLS:
            return SkillEnvelope(skill=skill, status="failed", unavailable=["skill_not_executable"])
        if self.calls >= MAX_SKILL_CALLS:
            return SkillEnvelope(skill=skill, status="partial", unavailable=["skill_budget_exhausted"])
        self.calls += 1
        self.executed.append(skill)
        handler = getattr(self, f"_{skill.replace('-', '_')}")
        try:
            return await handler(params or {})
        except Exception:
            return SkillEnvelope(skill=skill, status="failed", unavailable=["skill_execution_failed"])

    # -- envelope helpers -------------------------------------------------
    def _envelope(
        self,
        skill: str,
        *,
        observations: list[tuple[str, dict[str, Any], str]],
        findings: list[InvestigationFinding] | None = None,
        gaps: list[str] | None = None,
        unavailable: list[str] | None = None,
        status: str = "completed",
    ) -> SkillEnvelope:
        stored = [
            Observation(
                evidence_id=self.store.add(kind, payload, skill=skill, fact=fact),
                fact=fact,
                kind=kind,
                observed=True,
                payload=payload,
            )
            for kind, payload, fact in observations
        ]
        return SkillEnvelope(
            skill=skill,
            status=status,  # type: ignore[arg-type]
            evidence_ids=[item.evidence_id for item in stored],
            observations=stored,
            findings=findings or [],
            gaps=gaps or [],
            unavailable=unavailable or [],
            meta={"skill_calls": self.calls, "traversals": self.traversals},
        )

    def _finding(self, indicator: str, severity: str, evidence_ids: list[str], interpretation: str = "") -> InvestigationFinding:
        return InvestigationFinding(
            indicator=indicator[:500],
            severity=severity,  # type: ignore[arg-type]
            confidence="medium",
            evidence_ids=[item for item in evidence_ids if self.store.exists(item)],
            interpretation=interpretation[:800],
        )

    # -- evidence skills --------------------------------------------------
    async def _inspect_navigation(self, params: dict[str, Any]) -> SkillEnvelope:
        target = str(params.get("url") or "")
        if target:
            outcome = await self._traverse(target)
            if outcome is not None:
                return outcome
        chain = self.browser.get("redirect_chain") or []
        final_url = str(self.browser.get("final_url") or self.url)
        hops = [
            {
                "url": str(hop.get("url") or "")[:2048],
                "status": hop.get("status"),
                "host": det.normalize_host(str(hop.get("url") or "")),
            }
            for hop in chain
            if isinstance(hop, dict)
        ]
        payload = {
            "requested_url": self.url[:2048],
            "hops": hops[:10],
            "final_url": final_url[:2048],
            "final_host": det.normalize_host(final_url),
            "host_changed": det.normalize_host(final_url) != self.page_host,
            "failure": self.browser.get("error"),
            "screenshot_url": self.browser.get("screenshot_path"),
        }
        return self._envelope(
            "inspect-navigation",
            observations=[("nav", payload, "navigation")],
            gaps=[] if hops or final_url else ["navigation_unavailable"],
        )

    async def _traverse(self, target: str) -> SkillEnvelope | None:
        if self.traversals >= 1:
            return SkillEnvelope(skill="inspect-navigation", status="partial", unavailable=["traversal_budget_exhausted"])
        host = det.normalize_host(target)
        if (
            not host
            or det.is_private_or_invalid_host(host)
            or not det.same_registrable_domain(host, self.page_host)
            or target in self._traversed
        ):
            return SkillEnvelope(skill="inspect-navigation", status="failed", unavailable=["traversal_rejected"])
        self.traversals += 1
        self._traversed.add(target)
        from ..browser_client import inspect_website

        try:
            evidence = await inspect_website(target, self.scan_id, self.user_id)
        except Exception:
            return SkillEnvelope(skill="inspect-navigation", status="failed", unavailable=["traversal_failed"])
        for key in (
            "forms", "network_requests", "external_domains", "js_obfuscation",
            "redirect_chain", "final_url", "title", "visible_text", "links",
            "headings", "meta", "logo_candidates", "iframes",
        ):
            if key in evidence:
                self.browser[key] = evidence[key]
        payload = {
            "requested_url": target[:2048],
            "final_url": str(evidence.get("final_url") or target)[:2048],
            "final_host": det.normalize_host(str(evidence.get("final_url") or target)),
            "hops": [
                {"url": str(hop.get("url") or "")[:2048], "status": hop.get("status")}
                for hop in (evidence.get("redirect_chain") or [])
                if isinstance(hop, dict)
            ][:10],
            "failure": evidence.get("error"),
            "traversed_from": self.url[:2048],
        }
        return self._envelope("inspect-navigation", observations=[("nav", payload, "navigation_traversal")])

    async def _inspect_page_content(self, _params: dict[str, Any]) -> SkillEnvelope:
        payload = {
            "title": str(self.browser.get("title") or "")[:300],
            "meta": self.browser.get("meta") or {},
            "headings": [str(item)[:200] for item in (self.browser.get("headings") or [])][:30],
            "visible_text_excerpt": str(self.browser.get("visible_text") or "")[:MAX_TEXT_EXCERPT],
            "logo_candidates": self.browser.get("logo_candidates") or [],
            "links": [
                {"href": str(item.get("href") or "")[:2048], "text": str(item.get("text") or "")[:120]}
                for item in (self.browser.get("links") or [])
            ][:60],
        }
        gaps = [] if payload["title"] or payload["visible_text_excerpt"] else ["no_static_content"]
        return self._envelope("inspect-page-content", observations=[("page", payload, "page_identity")], gaps=gaps)

    async def _inspect_form_elements(self, _params: dict[str, Any]) -> SkillEnvelope:
        forms = []
        for form in self.browser.get("forms") or []:
            if not isinstance(form, dict):
                continue
            action = det.resolve_action(str(form.get("action") or ""), self.url)
            action_host = det.normalize_host(action)
            types = list(form.get("input_types") or [])
            names = list(form.get("input_names") or [])
            placeholders = list(form.get("input_placeholders") or [])
            fields = [
                {
                    "type": str(types[index] if index < len(types) else "text")[:24],
                    "name": _field_name(names[index] if index < len(names) else ""),
                    "placeholder": _field_name(placeholders[index] if index < len(placeholders) else ""),
                }
                for index in range(max(len(types), len(names), len(placeholders)))
            ][:20]
            forms.append(
                {
                    "method": str(form.get("method") or "GET").upper()[:8],
                    "action": action[:2048],
                    "action_host": action_host,
                    "cross_host": bool(action_host and action_host != self.page_host),
                    "password_fields": min(20, int(form.get("password_fields") or 0)),
                    "has_email": bool(form.get("has_email")),
                    "has_username": bool(form.get("has_username")),
                    "has_otp": bool(form.get("has_otp")),
                    "fields": fields,
                    "sensitive_categories": det.form_sensitive_categories(form),
                }
            )
        payload = {
            "page_host": self.page_host,
            "forms": forms[:20],
            "iframe_forms": len(self.browser.get("iframes") or []),
            "shadow_root_forms": int(self.browser.get("shadow_root_count") or 0),
        }
        return self._envelope(
            "inspect-form-elements",
            observations=[("form", payload, "form_inventory")],
            gaps=["forms_truncated"] if len(forms) > 20 else [],
        )

    async def _inspect_network_activity(self, _params: dict[str, Any]) -> SkillEnvelope:
        requests = [
            {
                "url": str(item.get("url") or "")[:2048],
                "method": str(item.get("method") or "GET")[:12],
                "resource_type": str(item.get("resource_type") or "")[:24],
                "status": item.get("status"),
                "failed": bool(item.get("failed")),
            }
            for item in (self.browser.get("network_requests") or [])
            if isinstance(item, dict)
        ][:120]
        hosts: dict[str, dict[str, Any]] = {}
        for item in requests:
            host = det.normalize_host(item["url"])
            if not host:
                continue
            entry = hosts.setdefault(host, {"host": host, "count": 0, "methods": set(), "resource_types": set()})
            entry["count"] += 1
            entry["methods"].add(item["method"])
            entry["resource_types"].add(item["resource_type"])
        host_list = [
            {**entry, "methods": sorted(entry["methods"]), "resource_types": sorted(entry["resource_types"] - {""})}
            for entry in hosts.values()
        ]
        payload = {
            "page_host": self.page_host,
            "request_count": len(requests),
            "requests": requests,
            "hosts": sorted(host_list, key=lambda item: item["count"], reverse=True)[:30],
            "external_hosts": [item["host"] for item in host_list if item["host"] != self.page_host][:30],
            "blocked": self.browser.get("blocked_requests") or [],
            "failed": self.browser.get("failed_requests") or [],
            "websockets": [],
        }
        return self._envelope(
            "inspect-network-activity",
            observations=[("net", payload, "network_graph")],
            gaps=["network_empty"] if not requests else [],
        )

    async def _inspect_javascript_behavior(self, _params: dict[str, Any]) -> SkillEnvelope:
        script_hosts = sorted(
            {
                det.normalize_host(str(item.get("url") or ""))
                for item in (self.browser.get("network_requests") or [])
                if isinstance(item, dict) and item.get("resource_type") == "script"
            }
            - {""}
        )
        payload = {
            "js_obfuscation": self.browser.get("js_obfuscation") or {"detected": False, "patterns": []},
            "script_hosts": script_hosts[:30],
            "script_request_count": sum(
                1 for item in (self.browser.get("network_requests") or [])
                if isinstance(item, dict) and item.get("resource_type") == "script"
            ),
            "blocked_methods": self.browser.get("blocked_methods") or [],
        }
        return self._envelope("inspect-javascript-behavior", observations=[("js", payload, "javascript_behavior")])

    async def _inspect_embedded_content(self, _params: dict[str, Any]) -> SkillEnvelope:
        iframes = []
        for frame in self.browser.get("iframes") or []:
            if not isinstance(frame, dict):
                continue
            src = str(frame.get("src") or "")
            iframes.append(
                {
                    "src_host": det.normalize_host(src),
                    "origin": src[:2048],
                    "title": str(frame.get("title") or "")[:120],
                    "sandboxed": bool(frame.get("sandbox")),
                    "same_origin": det.same_registrable_domain(det.normalize_host(src), self.page_host),
                }
            )
        payload = {
            "page_host": self.page_host,
            "frames": iframes[:30],
            "shadow_root_count": int(self.browser.get("shadow_root_count") or 0),
            "cross_origin_origins": sorted({item["origin"] for item in iframes if not item["same_origin"] and item["origin"]})[:20],
        }
        return self._envelope("inspect-embedded-content", observations=[("embed", payload, "embedded_content")])

    # -- investigation skills ---------------------------------------------
    def _official_context(self) -> tuple[str, list[str], list[str]]:
        for item in self.deterministic_findings:
            source = getattr(item, "source", None) or (item.get("source") if isinstance(item, dict) else "")
            if source != "brand_guard":
                continue
            metadata = getattr(item, "metadata", None) or (item.get("metadata") if isinstance(item, dict) else {}) or {}
            brand = str(metadata.get("brand") or "")
            domains = [str(domain) for domain in (metadata.get("official_domains") or [])]
            if brand:
                return brand, domains, ["brand_guard"]
        text = f"{self.browser.get('title') or ''} {self.browser.get('visible_text') or ''}".casefold()
        brands = load_brands()
        best = ""
        for brand in brands:
            pattern = rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])"
            if len(brand) >= 3 and re.search(pattern, text) and len(brand) > len(best):
                best = brand
        return best, list(brands.get(best, [])), ["page_text_match"] if best else []

    async def _investigate_brand_impersonation(self, _params: dict[str, Any]) -> SkillEnvelope:
        brand, official_domains, sources = self._official_context()
        relation = det.domain_relation(self.page_host, official_domains) if brand else "unknown"
        rules = det.lookalike_rules(self.page_host, brand) if brand else []
        forms = det.sensitive_forms(self.browser, self.page_host)
        payload = {
            "claimed_brand": brand or None,
            "claim_sources": sources,
            "site_domain": det.registrable_domain(self.page_host),
            "official_domains": official_domains[:5],
            "domain_relation": relation,
            "lookalike_rules": rules,
            "sensitive_form_count": len(forms),
        }
        findings: list[InvestigationFinding] = []
        if brand and relation in {"unrelated", "lookalike"} and not det.same_registrable_domain(self.page_host, official_domains[0] if official_domains else ""):
            evidence_ids = [self.store.add("brand", payload, skill="investigate-brand-impersonation", fact="brand_identity_comparison")]
            severity = "high" if forms else "medium"
            findings.append(
                self._finding(
                    f"Situs mengklaim identitas {brand} pada domain yang tidak terdaftar sebagai domain resmi.",
                    severity,
                    evidence_ids,
                    "Perbandingan domain deterministik; severity naik bila ada form sensitif.",
                )
            )
            return self._envelope(
                "investigate-brand-impersonation",
                observations=[("brand", payload, "brand_identity_comparison")],
                findings=findings,
                gaps=[] if official_domains else ["official_domain_unverified"],
            )
        return self._envelope(
            "investigate-brand-impersonation",
            observations=[("brand", payload, "brand_identity_comparison")],
            gaps=["brand_unresolved"] if not brand else ([] if official_domains else ["official_domain_unverified"]),
        )

    async def _investigate_form_destination(self, _params: dict[str, Any]) -> SkillEnvelope:
        forms = det.sensitive_forms(self.browser, self.page_host)
        network_hosts = {
            det.normalize_host(str(item.get("url") or ""))
            for item in (self.browser.get("network_requests") or [])
            if isinstance(item, dict)
        }
        enriched = [{**form, "observed_contact": form["action_host"] in network_hosts} for form in forms]
        payload = {
            "page_host": self.page_host,
            "forms": enriched[:20],
            "declared_vs_observed": all(item["observed_contact"] for item in enriched) if enriched else None,
        }
        evidence_id = self.store.add("domain", payload, skill="investigate-form-destination", fact="form_destination_analysis")
        findings: list[InvestigationFinding] = []
        for form in enriched:
            categories = set(form["sensitive_categories"])
            if form["destination"] != "third_party_unknown":
                continue
            if categories & {"password", "otp"}:
                findings.append(
                    self._finding(
                        "Formulir kredensial mengirim data ke domain pihak ketiga yang tidak terkait dengan situs.",
                        "high",
                        [evidence_id],
                        f"Action {form['action_host']} menerima kategori {', '.join(sorted(categories))}.",
                    )
                )
            elif categories:
                findings.append(
                    self._finding(
                        "Formulir berisi data identitas dan mengirimkannya ke domain pihak ketiga.",
                        "medium",
                        [evidence_id],
                        f"Action {form['action_host']}.",
                    )
                )
        return self._envelope(
            "investigate-form-destination",
            observations=[("domain", payload, "form_destination_analysis")],
            findings=findings[:4],
            gaps=["action_unresolved"] if any(form["destination"] == "private_or_invalid" for form in enriched) else [],
        )

    async def _investigate_redirect_chain(self, _params: dict[str, Any]) -> SkillEnvelope:
        facts = det.redirect_facts(self.browser.get("redirect_chain") or [], self.page_host)
        payload = {
            "page_host": self.page_host,
            **facts,
            "final_destination": str(self.browser.get("final_url") or self.url)[:2048],
        }
        evidence_id = self.store.add("redirect", payload, skill="investigate-redirect-chain", fact="redirect_chain_analysis")
        findings: list[InvestigationFinding] = []
        sensitive = det.sensitive_forms(self.browser, self.page_host)
        if facts["registrable_domain_changes"]:
            severity = "high" if sensitive else "medium"
            findings.append(
                self._finding(
                    "Rantai redirect berpindah domain sebelum halaman akhir dimuat.",
                    severity,
                    [evidence_id],
                    f"{facts['registrable_domain_changes']} perubahan registrable domain.",
                )
            )
        return self._envelope(
            "investigate-redirect-chain",
            observations=[("redirect", payload, "redirect_chain_analysis")],
            findings=findings,
            gaps=["chain_unavailable"] if not facts["hop_count"] else [],
        )

    async def _investigate_external_domains(self, _params: dict[str, Any]) -> SkillEnvelope:
        requests = [item for item in (self.browser.get("network_requests") or []) if isinstance(item, dict)]
        hosts: dict[str, dict[str, Any]] = {}
        for item in requests:
            host = det.normalize_host(str(item.get("url") or ""))
            if not host or host == self.page_host:
                continue
            entry = hosts.setdefault(host, {"host": host, "count": 0, "resource_types": set()})
            entry["count"] += 1
            entry["resource_types"].add(str(item.get("resource_type") or ""))
        forms = det.sensitive_forms(self.browser, self.page_host)
        data_destinations = {form["action_host"] for form in forms if form["action_host"] and form["action_host"] != self.page_host}
        domains = []
        for host, entry in list(hosts.items())[:30]:
            resources = sorted(entry["resource_types"] - {""})
            purpose = "collector" if host in data_destinations else ("cdn" if {"image", "script", "stylesheet", "font"} & set(resources) else "unknown")
            domains.append(
                {
                    "host": host,
                    "registrable_domain": det.registrable_domain(host),
                    "purpose": purpose,
                    "request_count": entry["count"],
                    "resource_types": resources,
                    "data_destination": host in data_destinations,
                }
            )
        payload = {"page_host": self.page_host, "domains": domains, "data_destinations": sorted(data_destinations)}
        evidence_id = self.store.add("domain", payload, skill="investigate-external-domains", fact="external_domain_attribution")
        findings: list[InvestigationFinding] = []
        if any(form["destination"] == "third_party_unknown" and set(form["sensitive_categories"]) for form in forms):
            findings.append(
                self._finding(
                    "Domain eksternal menerima data formulir sensitif dan tidak terkait dengan situs.",
                    "high",
                    [evidence_id],
                    "Peran collector didukung oleh aksi form dan trafik jaringan teramati.",
                )
            )
        return self._envelope(
            "investigate-external-domains",
            observations=[("domain", payload, "external_domain_attribution")],
            findings=findings,
            gaps=["hosts_truncated"] if len(hosts) > 30 else [],
        )
