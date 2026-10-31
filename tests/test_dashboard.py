"""Exercise real Streamlit reruns, controls and evidence rendering."""
from pathlib import Path
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")


def test_dashboard_analysis_and_navigation():
    app = AppTest.from_file(APP, default_timeout=30).run()
    assert not app.exception
    assert len(app.metric) == 0
    app.button[0].click().run()
    assert not app.exception
    assert len(app.metric) >= 4
    assert app.metric[0].value == "500"
    app.checkbox[0].uncheck().run()
    assert not app.exception
    app.sidebar.slider[0].set_value(2.5).run()
    assert any("previous run" in warning.value for warning in app.warning)
    app.sidebar.radio[0].set_value("Domain inspector").run()
    assert not app.exception
    app.button[0].click().run()
    assert not app.exception
    assert any("61646d" in heading.value for heading in app.subheader)
    app.sidebar.radio[0].set_value("Method & project").run()
    assert not app.exception


def test_dashboard_no_silent_upload_fallback():
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.selectbox[0].set_value("Upload CSV").run()
    app.button[0].click().run()
    assert not app.exception
    assert any("Choose a file" in error.value for error in app.error)
    assert not app.metric


def test_sample_pcap_runs_in_dashboard():
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.selectbox[0].set_value("Generate sample PCAP").run()
    app.button[0].click().run()
    assert not app.exception
    assert not app.error
    assert app.metric[0].value == "120"
    app.multiselect[0].set_value(app.multiselect[0].options[:1]).run()
    assert not app.exception
    assert app.code
