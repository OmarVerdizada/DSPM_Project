import { useState, useRef } from 'react'

const FAQS = [
  {
    q: 'How quickly can SENTRO discover our data?',
    a: 'SENTRO completes an initial discovery scan of a typical enterprise environment in under 30 minutes, with continuous real-time monitoring thereafter. No overnight scans, no scheduled windows.',
  },
  {
    q: 'What data sources does SENTRO support?',
    a: 'SENTRO supports cloud storage (AWS S3, Azure Blob, Google Cloud Storage), databases (PostgreSQL, MySQL, MSSQL, MongoDB, Redis), endpoints (Windows, macOS, Linux), and network shares (SMB, NFS). More connectors ship quarterly.',
  },
  {
    q: 'Does SENTRO read or store our sensitive data?',
    a: 'Never. SENTRO reads only metadata and pattern signatures — it never stores, transmits, or retains the actual content of sensitive files or records. Your data stays in your environment, always.',
  },
  {
    q: 'Is SENTRO compliant with GDPR, HIPAA, and SOC 2?',
    a: 'SENTRO is built to help you achieve compliance, with native mapping to GDPR Article 30 records of processing, HIPAA Security Rule safeguards, and SOC 2 Trust Services Criteria. Compliance reports are one click away.',
  },
]

export default function FAQ() {
  const [openIndex, setOpenIndex] = useState<number | null>(null)

  return (
    <section
      id="faq"
      className="relative py-32 px-6"
    >
      <div className="max-w-3xl mx-auto">
        <div className="text-center mb-16">
          <p className="section-label">FAQ</p>
          <h2 className="font-display text-fluid-lg text-text-primary tracking-tight">
            Common Questions
          </h2>
        </div>

        <div className="space-y-3">
          {FAQS.map((faq, i) => (
            <FAQItem
              key={faq.q}
              question={faq.q}
              answer={faq.a}
              isOpen={openIndex === i}
              onToggle={() => setOpenIndex(openIndex === i ? null : i)}
            />
          ))}
        </div>
      </div>
    </section>
  )
}

interface FAQItemProps {
  question: string
  answer: string
  isOpen: boolean
  onToggle: () => void
}

function FAQItem({ question, answer, isOpen, onToggle }: FAQItemProps) {
  const answerRef = useRef<HTMLDivElement>(null)

  return (
    <div
      className="rounded-xl overflow-hidden transition-all duration-300"
      style={{
        background: isOpen ? 'rgba(15,22,41,0.9)' : 'rgba(15,22,41,0.5)',
        border: `1px solid ${isOpen ? 'rgba(59,130,246,0.3)' : 'rgba(37,99,235,0.12)'}`,
        boxShadow: isOpen ? '0 0 30px rgba(59,130,246,0.06)' : 'none',
      }}
    >
      <button
        className="w-full flex items-center justify-between px-6 py-5 text-left"
        onClick={onToggle}
        aria-expanded={isOpen}
      >
        <span className="font-medium text-text-primary text-sm leading-snug pr-4">
          {question}
        </span>
        <svg
          width="20"
          height="20"
          viewBox="0 0 20 20"
          fill="none"
          className="flex-none transition-transform duration-300"
          style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}
          aria-hidden="true"
        >
          <path
            d="M5 7.5l5 5 5-5"
            stroke={isOpen ? '#38BDF8' : '#64748B'}
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>

      <div
        ref={answerRef}
        style={{
          maxHeight: isOpen ? '300px' : '0',
          overflow: 'hidden',
          transition: 'max-height 0.38s cubic-bezier(0.4,0,0.2,1)',
        }}
      >
        <p className="px-6 pb-5 text-text-secondary text-sm leading-relaxed">
          {answer}
        </p>
      </div>
    </div>
  )
}
