import streamlit as st
import hashlib
import json
import qrcode
from io import BytesIO
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from pyzbar.pyzbar import decode
from PIL import Image

class DegreeVerificationSystem:
    def __init__(self):
        if "private_key" not in st.session_state:
            key_pair = RSA.generate(2048)
            st.session_state["private_key"] = key_pair.export_key()
            st.session_state["public_key"] = key_pair.publickey().export_key()
        self.private_key = st.session_state["private_key"]
        self.public_key = st.session_state["public_key"]
        if "blockchain" not in st.session_state:
            st.session_state["blockchain"] = []
        self.__blockchain = st.session_state["blockchain"]

    def generate_hash(self, reg_no, name, marks, aadhaar_no):
        prev_hash = self.__blockchain[-1] if self.__blockchain else "GENESIS"
        student_data = f"{reg_no}|{name}|{marks}|{aadhaar_no}|{prev_hash}"
        student_hash = hashlib.sha256(student_data.encode()).hexdigest()
        return student_hash

    def sign_certificate(self, student_hash):
        private_key_obj = RSA.import_key(self.private_key)
        hash_obj = SHA256.new(student_hash.encode())
        signature = pkcs1_15.new(private_key_obj).sign(hash_obj)
        return signature.hex()

    def generate_qr_certificate(self, reg_no, name, marks, aadhaar_no):
        student_hash = self.generate_hash(reg_no, name, marks, aadhaar_no)
        signature = self.sign_certificate(student_hash)
        self.__blockchain.append(student_hash)
        certificate = {
            "reg_no": reg_no,
            "name": name,
            "marks": marks,
            "aadhaar_no": aadhaar_no,
            "student_hash": student_hash,
            "signature": signature
        }
        cert_json = json.dumps(certificate)
        qr = qrcode.make(cert_json)
        qr_img = BytesIO()
        qr.save(qr_img, format="PNG")
        qr_img.seek(0)
        return qr_img

    def verify_qr_certificate(self, cert_json):
        try:
            cert_data = json.loads(cert_json)
            student_hash = cert_data["student_hash"]
            signature = bytes.fromhex(cert_data["signature"])
            public_key_obj = RSA.import_key(self.public_key)
            hash_obj = SHA256.new(student_hash.encode())
            pkcs1_15.new(public_key_obj).verify(hash_obj, signature)
            return True, "✅ Verification successful: Degree is valid!"
        except (ValueError, TypeError, json.JSONDecodeError, KeyError):
            return False, "❌ Verification failed: Degree is invalid or corrupted!"

    def scan_qr_code(self, file):
        try:
            img = Image.open(file)
            qr_data = decode(img)
            if qr_data:
                return qr_data[0].data.decode("utf-8")
            return None
        except Exception as e:
            return None

st.title("🎓 Degree Verification System")
system = DegreeVerificationSystem()
mode = st.radio("Select Mode", ["College Mode", "Company Mode"])

if mode == "College Mode":
    st.header("Generate Degree Certificate QR Code")
    reg_no = st.text_input("Registration Number")
    name = st.text_input("Student Name")
    marks = st.text_input("Marks (%)")
    aadhaar_no = st.text_input("Aadhaar Number")
    if st.button("Generate QR Code"):
        if reg_no and name and marks and aadhaar_no:
            qr_img = system.generate_qr_certificate(reg_no, name, marks, aadhaar_no)
            st.image(qr_img, caption="Generated QR Code", use_column_width=True)
            st.download_button("Download QR Code", data=qr_img, file_name=f"{reg_no}_degree_qr.png", mime="image/png")
        else:
            st.error("Please fill in all fields.")

elif mode == "Company Mode":
    st.header("Verify Degree Certificate")
    uploaded_file = st.file_uploader("Upload QR Code Image", type=["png", "jpg", "jpeg"])
    if uploaded_file is not None:
        cert_json = system.scan_qr_code(uploaded_file)
        if cert_json:
            is_valid, message = system.verify_qr_certificate(cert_json)
            st.image(uploaded_file, caption="Uploaded QR Code", use_column_width=True)
            if is_valid:
                st.success(message)
            else:
                st.error(message)
        else:
            st.error("No QR code detected or invalid file. Please upload a valid QR code image.")
