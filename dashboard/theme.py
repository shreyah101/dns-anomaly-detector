"""Consistent dark surfaces for the application and embedded charts."""
import altair as alt
import streamlit as st

BACKGROUND = "#0e141d"
SURFACE = "#172130"
TEXT = "#e4ecf5"
MUTED = "#a3b2c5"
BORDER = "#2b3a4f"
BLUE = "#82b4ff"
AMBER = "#efb879"


def apply_dark_theme():
    # Hide Streamlit's theme switcher; this application has one visual theme.
    st.set_option("client.toolbarMode", "minimal")
    st.markdown("""<style>
    :root {color-scheme: dark;}
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background: #0e141d; color: #e4ecf5;
        --background-color: #0e141d;
        --secondary-background-color: #172130;
        --text-color: #e4ecf5;
        --primary-color: #82b4ff;
    }
    .block-container {max-width: 1440px; padding-top: 2.2rem;}
    h1 {letter-spacing: -.045em; font-weight: 650 !important;}
    h2, h3 {letter-spacing: -.025em;}
    h1, h2, h3, label {color: #e4ecf5 !important;}
    [data-testid="stCaptionContainer"] {color: #a3b2c5;}
    [data-testid="stSidebar"] {background: #121b28; border-right: 1px solid #2b3a4f;}
    [data-testid="stMetric"] {
        background: #172130; border: 1px solid #2b3a4f;
        border-radius: 8px; padding: 18px;
    }
    [data-testid="stMetricLabel"] {font-size: .85rem; color: #a3b2c5;}
    [data-testid="stMetricValue"] {color: #e4ecf5;}
    [data-testid="stVerticalBlockBorderWrapper"] > div {border-color: #2b3a4f;}
    [data-baseweb="input"], [data-baseweb="select"] > div,
    [data-testid="stFileUploaderDropzone"] {background-color: #172130; color: #e4ecf5;}
    .stButton > button, .stDownloadButton > button {border-radius: 6px;}
    #MainMenu {display: none;}
    </style>""", unsafe_allow_html=True)


def style_axes(fig, ax):
    fig.set_facecolor(BACKGROUND)
    ax.set_facecolor(BACKGROUND)
    ax.tick_params(colors=MUTED)
    ax.xaxis.label.set_color(MUTED)
    ax.yaxis.label.set_color(MUTED)
    for spine in ax.spines.values():
        spine.set_color(BORDER)
    legend = ax.get_legend()
    if legend:
        for label in legend.get_texts():
            label.set_color(TEXT)


def line_chart(frame, x, y, x_title, y_title, series=None):
    chart = alt.Chart(frame).mark_line(point=len(frame) < 3).encode(
        x=alt.X(x, title=x_title, scale=alt.Scale(type="utc") if x.endswith(":T") else alt.Undefined),
        y=alt.Y(y, title=y_title),
        tooltip=list(frame.columns),
    )
    if series:
        chart = chart.encode(color=alt.Color(series, title=None,
                            scale=alt.Scale(range=[BLUE, AMBER])))
    else:
        chart = chart.encode(color=alt.value(BLUE))
    chart = (chart.properties(height=260, background=BACKGROUND)
             .configure_view(stroke=None)
             .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=BORDER,
                             domainColor=BORDER, tickColor=BORDER)
             .configure_legend(labelColor=TEXT, titleColor=TEXT))
    st.altair_chart(chart, theme=None, use_container_width=True)
