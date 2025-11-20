mport streamlit as st
import hashlib
import itertools
import csv
import io

# -------------------------
# Helper Functions
# -------------------------

def hash_password(password: str, algo="sha256") -> str:
    """Hash a password with the given algorithm"""
    return hashlib.new(algo, password.encode()).hexdigest()


def dictionary_attack(target_hash, dictionary_file, algo="sha256"):
    """Try dictionary attack"""
    for word in dictionary_file.getvalue().decode("utf-8").splitlines():
        word = word.strip()
        if hash_password(word, algo) == target_hash:
            return word
    return None


def brute_force_attack(target_hash, max_length=4, algo="sha256", progress_callback=None):
    """Brute-force attack simulation with progress bar"""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    total = sum(len(chars) ** i for i in range(1, max_length + 1))
    tried = 0

    for length in range(1, max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            pwd = "".join(attempt)
            tried += 1
            if progress_callback:
                progress_callback(tried, total)
            if hash_password(pwd, algo) == target_hash:
                return pwd
    return None


def password_strength(password: str) -> str:
    """Check password strength"""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    score = sum([has_upper, has_lower, has_digit, has_special])

    if length < 4 or score < 2:
        return "Weak"
    elif length < 8 or score < 3:
        return "Medium"
    else:
        return "Strong"


def export_results(results, filetype="txt"):
    """Export results into .txt or .csv and return as download link"""
    output = io.StringIO()
    if filetype == "txt":
        for pwd, category in results:
            output.write(f"{pwd}: {category}\n")
    elif filetype == "csv":
        writer = csv.writer(output)
        writer.writerow(["Password", "Category"])
        writer.writerows(results)
    return output.getvalue()


# -------------------------
# Streamlit App
# -------------------------
def main():
    st.title("🔐 Password Analyzer - Dictionary & Brute Force Attack")

    st.sidebar.header("Options")
    target_hash = st.sidebar.text_input("Enter Target Hash (SHA256)")

    # Results storage
    if "results" not in st.session_state:
        st.session_state.results = []

    # Dictionary Attack
    st.subheader("📖 Dictionary Attack")
    dictionary_file = st.file_uploader("Upload Dictionary File", type=["txt"])
    if st.button("Run Dictionary Attack"):
        if not target_hash:
            st.warning("Please enter a target hash first!")
        elif not dictionary_file:
            st.warning("Please upload a dictionary file!")
        else:
            result = dictionary_attack(target_hash, dictionary_file)
            if result:
                st.success(f"[+] Dictionary Attack Success: {result}")
            else:
                st.error("[-] Dictionary Attack Failed")

    # Brute Force Attack
    st.subheader("💥 Brute Force Attack")
    max_len = st.slider("Max Password Length", 1, 5, 4)
    if st.button("Run Brute Force Attack"):
        if not target_hash:
            st.warning("Please enter a target hash first!")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()

            def update_progress(tried, total):
                percent = int((tried / total) * 100)
                progress_bar.progress(percent)
                status_text.text(f"Tried: {tried}/{total}")

            result = brute_force_attack(target_hash, max_length=max_len, progress_callback=update_progress)
            if result:
                st.success(f"[+] Brute Force Success: {result}")
            else:
                st.error("[-] Brute Force Failed")

    # Password Strength Checker
    st.subheader("🛡️ Password Strength Checker")
    pwd = st.text_input("Enter a Password")
    if st.button("Check Strength"):
        if not pwd:
            st.warning("Enter a password first!")
        else:
            category = password_strength(pwd)
            st.session_state.results.append((pwd, category))
            st.info(f"Password: {pwd} → {category}")

    # Export Results
    st.subheader("📤 Export Results")
    filetype = st.radio("Choose Export Format", ["txt", "csv"])
    if st.button("Export Results"):
        if not st.session_state.results:
            st.warning("No results to export!")
        else:
            data = export_results(st.session_state.results, filetype)
            st.download_button("Download File", data, f"results.{filetype}", mime="text/plain")


if __name__ == "__main__":
    main()