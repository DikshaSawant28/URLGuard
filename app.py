import streamlit as st
import ipaddress
import difflib
from virustotal import check_url

st.set_page_config(
    page_title="URLGuard",
    layout="wide"
)
if "analysis_history" not in st.session_state:
    st.session_state.analysis_history = []

st.title("URLGuard")
st.subheader("Phishing URL Risk Analyzer")

st.write("Analyze a website URL and identify common phishing risk indicators.")

url = st.text_input(
    "Website URL",
    placeholder="https://example.com" 
) 
 
 
def analyze_url(url): 
    score = 0 
    findings = [] 
 
    # Check URL length 
    if len(url) > 75: 
        score += 10 
        findings.append("URL is unusually long") 
 
    # Check special character @ 
    if "@" in url: 
        score += 15 
        findings.append("URL contains @ symbol") 
 
    # Check for IP address 
    try: 
        hostname = url.split("//")[-1].split("/")[0].split(":")[0] 
        ipaddress.ip_address(hostname) 
        score += 20 
        findings.append("URL uses an IP address instead of a domain") 
    except ValueError: 
        pass 
 
    # Check suspicious keywords 
    suspicious_words = [ 
        "login", 
        "verify", 
        "account", 
        "update", 
        "secure", 
        "password" 
    ] 
 
    found_words = [] 
 
    for word in suspicious_words: 
        if word in url.lower(): 
            found_words.append(word) 
 
    if found_words: 
        score += 10 
        findings.append( 
            "Suspicious keyword found: " + ", ".join(found_words) 
        ) 
 
    # Check HTTPS 
    if not url.lower().startswith("https://"): 
        score += 5 
        findings.append("URL does not use HTTPS") 

    # Check for typosquatting
    try:
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        domain = hostname.lower().replace("www.", "").split(".")[0]
        normalized_domain = domain.replace("0", "o").replace("1", "l")

        trusted_brands = ["google", "paypal", "microsoft", "facebook", "netflix", "amazon", "apple", "instagram"]

        for brand in trusted_brands:
            similarity = difflib.SequenceMatcher(None, normalized_domain, brand).ratio()
            
            if similarity >= 0.8 and domain != brand: 
                score += 15
                findings.append(
                    "Possible typosquatting detected: " + domain +
                    " may be impersonating " + brand
                )
                break

    except Exception:
        pass
    
    # Check for Punycode
    try:
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]

        if "xn--" in hostname.lower():
            score += 10
            findings.append("Possible homograph attack: Punycode domain detected")

    except Exception:
        pass

    
    try:
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        parts = hostname.split(".")

        if len(parts) >= 5:
            score += 15
            findings.append("URL contains too many subdomains")

    except Exception:
        pass
 
    # Keep score between 0 and 100 
    if score > 100: 
        score = 100 
 
    # Risk classification 
    if score >= 60: 
        risk = "High Risk" 
    elif score >= 30: 
        risk = "Medium Risk" 
    else: 
        risk = "Low Risk" 
 
    return score, risk, findings 
    
with st.expander("How URLGuard Works"):
    st.write("1. Enter a website URL")
    st.write("2. Check for phishing indicators")
    st.write("3. Calculate the risk score")
    st.write("4. Display the risk level")
    st.write("5. Show the detected indicators")

st.write("### Example URLs")
st.code("https://example.com")
st.code("http://example.com/login")
st.code("http://192.168.1.1/login")
st.code("https://g00gle.com")
 
 
if st.button("Analyze URL"):
 
    if url.strip(): 
 
        score, risk, findings = analyze_url(url.strip()) 

        if not st.session_state.analysis_history or st.session_state.analysis_history[-1][0] != url.strip():
            st.session_state.analysis_history.append(
                (url.strip(), score, risk)
            )
 
        st.success("URL analysis completed successfully!")
        
        st.write("### Analysis Result")
 
        st.metric("Risk Score", str(score) + " / 100")
 
        st.progress(score / 100) 
 
        st.subheader("Risk Level: " + risk)

        st.write("### Why was this URL flagged?")

        if findings:
            st.info("URLGuard detected the following risk indicators:")
        else:
            st.success("URLGuard did not detect any major risk indicators.") 
 
        st.write("### Findings")
 
        if findings:
            for finding in findings:
                st.warning(finding)
        else: 
            st.write("No major risk indicators detected.")   

        st.write("### VirusTotal Check")

        vt_result = check_url(url.strip())

        if vt_result:
            st.markdown(vt_result)
        else:
            st.warning("VirusTotal check could not be completed.")

        st.write("### Analysis History")

        if st.session_state.analysis_history:
            for history_url, history_score, history_risk in st.session_state.analysis_history:
                st.text(
                    f"{history_url} — {history_score}/100 — {history_risk}"
                )
        else:
            st.write("No URLs analyzed yet.")
 
    else: 
        st.warning("Please enter a URL first.")

        