"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import styles from "./intro.module.css";

const FEATURE_PILLS = [
  { icon: "49", label: "Behavioral Features" },
  { icon: "TLS", label: "Encrypted Traffic Ready" },
  { icon: "IP", label: "Pivot Tracking" },
  { icon: "RT", label: "Real-Time Blocking" },
];

const STATS = [
  { value: "49", label: "Behavioral Features" },
  { value: "99%", label: "Detection Rate" },
  { value: "0ms", label: "Payload Inspection" },
  { value: "100%", label: "Encrypted Traffic Coverage" },
];

const FEATURE_CARDS = [
  {
    title: "Behavioral Classification",
    text: "Classifies traffic using flow behavior instead of packet payloads, so visibility remains strong even when sessions are encrypted.",
  },
  {
    title: "Identity-Centric Tracking",
    text: "Groups network activity around persistent identities and highlights changes in trust posture across repeat interactions.",
  },
  {
    title: "Live Capture Workflow",
    text: "Moves from capture to analysis to analyst action in one dashboard, reducing the gap between detection and response.",
  },
];

const DIFFERENTIATORS = [
  {
    title: "No payload dependency",
    text: "Obsidian Lens is designed for modern encrypted traffic and does not depend on deep packet inspection to stay useful.",
  },
  {
    title: "Pivot-aware forensics",
    text: "The system keeps context as infrastructure changes, helping analysts follow suspicious identities through IP movement.",
  },
  {
    title: "Actionable response layer",
    text: "The dashboard is not just descriptive. It supports triage, review, and immediate containment from the same workspace.",
  },
];

function StarRating({ count = 5 }) {
  return (
    <span className={styles.starRow}>
      {Array.from({ length: count }).map((_, index) => (
        <svg
          key={index}
          width="18"
          height="18"
          viewBox="0 0 20 20"
          fill="#F5A623"
        >
          <path d="M10 1l2.4 6.9H20l-5.9 4.2 2.3 6.9L10 14.8l-6.4 4.2 2.3-6.9L0 7.9h7.6z" />
        </svg>
      ))}
    </span>
  );
}

function Orbs() {
  return (
    <>
      <motion.div
        className={`${styles.floatingOrb} ${styles.orbOne}`}
        animate={{ y: [0, -20, 0] }}
        transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className={`${styles.floatingOrb} ${styles.orbTwo}`}
        animate={{ y: [0, 16, 0] }}
        transition={{ duration: 9, repeat: Infinity, ease: "easeInOut" }}
      />
    </>
  );
}

export default function HomePage() {
  return (
    <main className={styles.page}>
      <nav className={styles.nav}>
        <div className={styles.brandGroup}>
          <div className={styles.brandMark}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="4" fill="#c084fc" />
              <path
                d="M12 3v3M12 18v3M3 12h3M18 12h3"
                stroke="#c084fc"
                strokeWidth="2.5"
                strokeLinecap="round"
              />
            </svg>
          </div>
          <span className={styles.brandText}>OBSIDIAN LENS</span>
        </div>

        <div className={styles.navStatus}>Network forensic intelligence platform</div>
      </nav>

      <section className={styles.hero}>
        <Orbs />

        <div className={styles.heroGrid}>
          <motion.div
            initial={{ opacity: 0, x: -40 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.7 }}
            className={styles.cardColumn}
          >
            <div className={styles.productCard}>
              <div className={styles.cardBlobTop} />
              <div className={styles.cardBlobBottom} />

              <div className={styles.productInner}>
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 22, repeat: Infinity, ease: "linear" }}
                >
                  <svg width="130" height="130" viewBox="0 0 130 130">
                    <circle cx="65" cy="65" r="56" fill="none" stroke="#9333ea" strokeWidth="1.5" strokeDasharray="6 5" />
                    <circle cx="65" cy="65" r="40" fill="#1a0533" />
                    <circle cx="65" cy="65" r="26" fill="#2e1065" />
                    <circle cx="65" cy="65" r="14" fill="#c084fc" />
                    <circle cx="65" cy="65" r="6" fill="white" />
                    <line x1="65" y1="9" x2="65" y2="28" stroke="#c084fc" strokeWidth="2.5" strokeLinecap="round" />
                    <line x1="65" y1="102" x2="65" y2="121" stroke="#c084fc" strokeWidth="2.5" strokeLinecap="round" />
                    <line x1="9" y1="65" x2="28" y2="65" stroke="#c084fc" strokeWidth="2.5" strokeLinecap="round" />
                    <line x1="102" y1="65" x2="121" y2="65" stroke="#c084fc" strokeWidth="2.5" strokeLinecap="round" />
                  </svg>
                </motion.div>
                <div className={styles.productName}>
                  OBSIDIAN
                  <br />
                  LENS
                </div>
                <div className={styles.versionPill}>v2.4.1 - STABLE RELEASE</div>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 40 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.7, delay: 0.15 }}
            className={styles.copyColumn}
          >
            <h1 className={styles.title}>THE OBSIDIAN LENS</h1>

            <div className={styles.ratingRow}>
              <span>Behavioral - ML-Powered - Real-Time Forensics</span>
              <StarRating count={5} />
            </div>

            <p className={styles.description}>
              Some tools scan packets. Ours reads behavior. The Obsidian Lens analyzes{" "}
              <strong>49 network features</strong> to classify threats without ever
              touching encrypted payloads, tracks attackers across IP pivots, and
              helps neutralize them the moment they are flagged.
            </p>

            <div className={styles.featurePills}>
              {FEATURE_PILLS.map((feature, index) => (
                <motion.span
                  key={feature.label}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.55 + index * 0.1 }}
                  className={styles.featurePill}
                >
                  <span className={styles.featureIcon}>{feature.icon}</span>
                  {feature.label}
                </motion.span>
              ))}
            </div>

            <div className={styles.freeTag}>FREE AND OPEN SOURCE</div>

            <div className={styles.ctaRow}>
              <motion.div
                whileHover={{ scale: 1.05, boxShadow: "0 6px 28px rgba(124,58,237,0.45)" }}
                whileTap={{ scale: 0.97 }}
              >
                <Link href="/dashboard" className={styles.primaryButton}>
                  Launch Dashboard
                </Link>
              </motion.div>
            </div>
          </motion.div>
        </div>

        <div className={styles.edgeOrbs} aria-hidden="true">
          {[
            { size: 88, color: "#a855f7", shift: "55%" },
            { size: 56, color: "#7c3aed", shift: "20%" },
            { size: 110, color: "#581c87", shift: "65%" },
            { size: 72, color: "#9333ea", shift: "30%" },
            { size: 50, color: "#c084fc", shift: "10%" },
            { size: 96, color: "#6b21a8", shift: "60%" },
            { size: 64, color: "#4c1d95", shift: "40%" },
          ].map((bubble, index) => (
            <motion.div
              key={index}
              className={styles.edgeOrb}
              style={{
                width: bubble.size,
                height: bubble.size,
                background: bubble.color,
                transform: `translateX(${bubble.shift})`,
              }}
              animate={{ y: [0, index % 2 === 0 ? -10 : 10, 0] }}
              transition={{ duration: 4 + index * 0.6, repeat: Infinity, ease: "easeInOut" }}
            />
          ))}
        </div>
      </section>

      <motion.section
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.9, duration: 0.6 }}
        className={styles.statsBar}
      >
        {STATS.map((stat) => (
          <div key={stat.label} className={styles.statItem}>
            <span className={styles.statValue}>{stat.value}</span>
            <span className={styles.statLabel}>{stat.label}</span>
          </div>
        ))}
      </motion.section>

      <section className={styles.contentSection}>
        <div className={styles.sectionHeader}>
          <span className={styles.sectionEyebrow}>Features</span>
          <h2 className={styles.sectionTitle}>Built for analysts who need clarity fast</h2>
          <p className={styles.sectionText}>
            The intro page now carries the full product story, from what the system
            does to why it stands apart in encrypted-network investigations.
          </p>
        </div>

        <div className={styles.cardGrid}>
          {FEATURE_CARDS.map((item) => (
            <article key={item.title} className={styles.infoCard}>
              <h3>{item.title}</h3>
              <p>{item.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className={styles.contentSection}>
        <div className={styles.sectionHeader}>
          <span className={styles.sectionEyebrow}>Differentiation</span>
          <h2 className={styles.sectionTitle}>Why Obsidian Lens feels different</h2>
          <p className={styles.sectionText}>
            It is designed around behavioral evidence, identity continuity, and a
            tight bridge from analysis to response.
          </p>
        </div>

        <div className={styles.differentiatorList}>
          {DIFFERENTIATORS.map((item, index) => (
            <article key={item.title} className={styles.differentiatorCard}>
              <span className={styles.diffIndex}>0{index + 1}</span>
              <div>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
              </div>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
