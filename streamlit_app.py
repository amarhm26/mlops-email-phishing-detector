import streamlit as st
import pandas as pd
from src.ingestion.fetch_and_predict_imap import fetch_and_predict  # make sure function name matches

st.set_page_config(page_title="Email Phishing Detector", page_icon="📧", layout="wide")

st.title("Email Phishing Detection")
st.write("Automatically fetch emails and predict if they're phishing or legitimate.")

if st.button("🔄 Fetch & Predict Emails"):
    with st.spinner("Fetching emails from your inbox..."):
        results = fetch_and_predict()  # uses credentials from .env

    if not results:
        st.warning("No emails found or connection issue.")
    else:
        df = pd.DataFrame(results)
        st.success(f"✅ {len(df)} new emails analyzed!")
        st.dataframe(df, use_container_width=True)

        # Download CSV
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Download Results as CSV",
            data=csv,
            file_name="email_predictions.csv",
            mime="text/csv",
        )
else:
    st.info("Click the button above to start fetching emails.")
