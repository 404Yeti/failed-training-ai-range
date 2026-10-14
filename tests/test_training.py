from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path

import pytest

from app.challenges import ChallengeRegistry
from app.main import app
from app.training import TRACKS, TrainingCatalog
from tests.test_app import run


class Links(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.links = []
        self.scripts = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            self.links.append(attrs.get("href", ""))
        if tag == "script":
            self.scripts.append(attrs.get("src", ""))


def test_catalog_associations_and_validation():
    challenges = ChallengeRegistry(Path("challenges"))
    catalog = TrainingCatalog(challenges)
    assert [track.id for track in catalog.tracks] == ["llm", "ml", "voice", "agents"]
    assert catalog.get("llm").modules == (
        ("PI-001", "BT-001"), ("PI-002", "BT-002"),
        ("II-001", "BT-003"), ("MT-001", "BT-004"),
        ("AG-001", "BT-005"), ("RT-001",),
    )
    assert [cid for module in catalog.get("llm").modules for cid in module] == [c.id for c in challenges.all()]
    with pytest.raises(ValueError, match="Duplicate track id"):
        TrainingCatalog(challenges, (TRACKS[0], TRACKS[0]))
    with pytest.raises(ValueError, match="Unknown challenge association"):
        TrainingCatalog(challenges, (replace(TRACKS[0], modules=(("NOPE",),)),))
    with pytest.raises(ValueError, match="Availability does not match"):
        TrainingCatalog(challenges, (replace(TRACKS[1], modules=(("PI-001",),)),))


def test_training_pages_links_and_legacy_contracts():
    async def scenario(client):
        hub = await client.get("/training")
        assert hub.status_code == 200
        assert "Choose your" in hub.text
        pages = [hub]
        for track in TRACKS:
            page = await client.get(f"/training/{track.id}")
            assert page.status_code == 200
            assert track.title.replace("&", "&amp;") in page.text
            assert not Links(page.text).scripts
            pages.append(page)
            if track.availability == "coming_soon":
                assert "Coming soon" in page.text
                assert "START LAB" not in page.text
                assert not any("/challenge/" in link for link in Links(page.text).links)
        foundations = pages[1]
        assert "06A" in foundations.text and "06B" not in foundations.text
        expected = [f"/challenge/{cid}" for module in TRACKS[0].modules for cid in module]
        actual = [link.removeprefix("http://test") for link in Links(foundations.text).links if "/challenge/" in link]
        assert actual == expected
        assert (await client.get("/")).text == foundations.text
        assert (await client.get("/training/unknown")).status_code == 404
        for path in expected:
            page = await client.get(path)
            assert page.status_code == 200
            assert 'href="/training/llm"' in page.text
            cid = path.rsplit("/", 1)[1]
            started = await client.post(f"/api/challenge/{cid}/start")
            assert started.status_code == 200
            data = started.json()
            assert data["challenge_id"] == cid
            assert data["compromised"] is False
            assert "session_id" in data and "flag" not in data
        for page in pages:
            assert 'name="viewport"' in page.text
            assert 'aria-label="Breadcrumb"' in page.text or page is hub
            for link in Links(page.text).links:
                if link.startswith("#"):
                    continue
                assert (await client.get(link)).status_code == 200, link
    run(scenario)


def test_catalog_templates_and_css():
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
    env = Environment(loader=FileSystemLoader("app/templates"), undefined=StrictUndefined)
    for name in env.list_templates():
        env.get_template(name)
    css = Path("app/static/style.css").read_text()
    assert css.count("{") == css.count("}")
    assert ":focus-visible" in css
    assert "@media(max-width:720px)" in css
    assert "grid-template-columns:repeat(2,minmax(0,1fr))" in css
