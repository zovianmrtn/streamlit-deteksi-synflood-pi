import streamlit as st
import pandas as pd
import joblib
import tempfile
import os
from scapy.all import rdpcap, IP, TCP

# ============================================
# KONFIGURASI HALAMAN
# ============================================
st.set_page_config(
    page_title="Deteksi Serangan SYN-Flood",
    page_icon="🛡️",
    layout="centered"
)

# ============================================
# LOAD MODEL
# ============================================
@st.cache_resource
def load_model():
    model_path = os.path.join(os.path.dirname(__file__), 'model_rf_v2.pkl')
    return joblib.load(model_path)

rf_model = load_model()

# ============================================
# FUNGSI EKSTRAK FITUR DARI PCAP
# ============================================
def extract_features(filepath):
    packets = rdpcap(filepath)
    data = []

    for p in packets:
        if IP in p and TCP in p:
            flags = p[TCP].flags
            data.append({
                'src_ip'   : p[IP].src,
                'dst_ip'   : p[IP].dst,
                'pkt_len'  : len(p),
                'ttl'      : p[IP].ttl,
                'window'   : p[TCP].window,
                'flag_syn' : 1 if flags & 0x02 else 0,
                'flag_ack' : 1 if flags & 0x10 else 0,
                'flag_fin' : 1 if flags & 0x01 else 0,
                'flag_rst' : 1 if flags & 0x04 else 0,
                'flag_psh' : 1 if flags & 0x08 else 0,
                'dst_port' : p[TCP].dport,
                'src_port' : p[TCP].sport,
            })

    return pd.DataFrame(data)

# ============================================
# TAMPILAN APLIKASI
# ============================================
st.title("🛡️ Sistem Deteksi Serangan SYN-Flood")
st.markdown("**Berbasis Algoritma Random Forest**")
st.markdown("---")

st.markdown("""
Aplikasi ini mendeteksi apakah trafik jaringan dalam file **.pcap** 
merupakan trafik **normal** atau mengandung **serangan DoS SYN-Flood**.
""")

# Upload file
st.subheader("📂 Upload File .pcap")
uploaded_file = st.file_uploader(
    "Pilih file .pcap untuk dianalisis",
    type=["pcap", "pcapng"]
)

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    with st.spinner("Menganalisis trafik jaringan..."):
        df = extract_features(tmp_path)
        os.unlink(tmp_path)

    if df.empty:
        st.error("❌ Tidak ada paket TCP/IP yang ditemukan dalam file ini!")
    else:
        # Fitur untuk prediksi, tanpa IP
        feature_cols = [
            'pkt_len', 'ttl', 'window', 'flag_syn', 'flag_ack',
            'flag_fin', 'flag_rst', 'flag_psh', 'dst_port', 'src_port'
        ]

        preds = rf_model.predict(df[feature_cols])

        total = len(preds)
        n_normal = int(sum(preds == 0))
        n_attack = int(sum(preds == 1))

        pct_normal = round(n_normal / total * 100, 2)
        pct_attack = round(n_attack / total * 100, 2)

        df['prediksi'] = ['🔴 Serangan' if p == 1 else '🟢 Normal' for p in preds]

        df_attack_result = df[df['prediksi'] == '🔴 Serangan'].reset_index(drop=True)
        df_normal_result = df[df['prediksi'] == '🟢 Normal'].reset_index(drop=True)

        # Keputusan akhir hanya 2 kategori
        is_attack_detected = n_attack >= n_normal

        st.markdown("---")
        st.subheader("📊 Hasil Analisis")

        # Metrik
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Paket", f"{total:,}")
        col2.metric("Trafik Normal", f"{n_normal:,}", f"{pct_normal}%")
        col3.metric("Trafik Serangan", f"{n_attack:,}", f"{pct_attack}%", delta_color="inverse")

        st.markdown("---")

        # Status deteksi, hanya normal atau serangan
        if is_attack_detected:
            st.error("## ⚠️ SERANGAN SYN-FLOOD TERDETEKSI!")
            st.markdown(f"**{pct_attack}%** dari total trafik teridentifikasi sebagai serangan.")
        else:
            st.success("## ✅ TRAFIK NORMAL")
            st.markdown(f"**{pct_normal}%** dari total trafik teridentifikasi sebagai normal.")

        st.markdown("---")

        # Top IP Penyerang hanya muncul kalau hasil akhirnya serangan
        if is_attack_detected and not df_attack_result.empty:
            st.subheader("🔍 Top IP Penyerang")
            top_ips = df_attack_result['src_ip'].value_counts().head(5).reset_index()
            top_ips.columns = ['IP Sumber', 'Jumlah Paket Serangan']
            st.dataframe(top_ips, use_container_width=True)
            st.markdown("---")

        # Tabel sample
        st.subheader("📋 Sample Data dan Hasil Prediksi")

        if is_attack_detected:
            # Jika serangan dominan, tampilkan serangan lebih dulu
            df_display = pd.concat([
                df_attack_result.head(15),
                df_normal_result.head(5)
            ]).reset_index(drop=True)
        else:
            # Jika normal dominan, tampilkan normal lebih dulu
            df_display = pd.concat([
                df_normal_result.head(15),
                df_attack_result.head(5)
            ]).reset_index(drop=True)

        st.dataframe(df_display, use_container_width=True)
        st.caption(
            f"Menampilkan 20 sample dari {total:,} total paket — "
            f"diurutkan berdasarkan hasil prediksi dominan."
        )

# Footer
st.markdown("---")
st.caption("Reyhan Zovian Martin | Universitas Gunadarma | Teknik Informatika | 2026")