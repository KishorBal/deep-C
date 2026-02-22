import { useState } from "react";
import API from "../api";

export default function Dashboard() {

  const [file, setFile] = useState(null);
  const [aiReview, setAiReview] = useState(false);
  const [summary, setSummary] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);
    formData.append("ai_review", aiReview);

    setLoading(true);
    setSummary("Initiating Deep-C scan...");

    try {
      const res = await API.post("/scan", formData);
      setResults(res.data.results);
      const lines = res.data.stdout.split("\n").slice(0, 6).join("\n");
      setSummary(lines);
    } catch (err) {
      setSummary("Error: " + err.message);
    }

    setLoading(false);
  };

  return (
    <div className="min-h-screen p-10">

      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-accent tracking-wide">
          Deep-C AI
        </h1>
        <p className="text-gray-400 mt-2">
          Advanced Android Deep Link Security Auditor
        </p>
        <p className="text-xs text-gray-500 mt-1">
          © Kishor Balan — Offensive Security Research
        </p>
      </div>

      <div className="grid grid-cols-3 gap-8">

        <div className="glass p-8 col-span-1 shadow-2xl">

          <h2 className="text-xl font-semibold text-accent mb-8">
            Audit Configuration
          </h2>

          {/* Premium Drag & Drop Upload */}
<div
  onDragOver={(e) => e.preventDefault()}
  onDrop={(e) => {
    e.preventDefault();
    const dropped = e.dataTransfer.files[0];
    if (dropped && dropped.name.endsWith(".apk")) {
      setFile(dropped);
    }
  }}
  className="relative group border-2 border-dashed border-white/10 
             hover:border-accent transition-all duration-300 
             rounded-2xl p-10 text-center cursor-pointer 
             bg-white/5 backdrop-blur-xl 
             hover:shadow-[0_0_30px_rgba(0,255,198,0.35)]"
>
  {!file ? (
    <>
      <div className="w-16 h-16 mx-auto mb-5 flex items-center justify-center 
                      rounded-full bg-accent/20 text-accent text-3xl">
        📦
      </div>

      <p className="text-lg font-semibold text-gray-200">
        Drag & Drop APK
      </p>
      <p className="text-sm text-gray-400 mt-2">
        or click to browse
      </p>
    </>
  ) : (
    <>
      <div className="text-accent text-3xl mb-2">✔</div>
      <p className="text-sm text-gray-200">{file.name}</p>
      <p className="text-xs text-gray-500 mt-1">
        {(file.size / 1024 / 1024).toFixed(2)} MB
      </p>
    </>
  )}

  <input
    type="file"
    accept=".apk"
    onChange={(e) => setFile(e.target.files[0])}
    className="absolute inset-0 opacity-0 cursor-pointer"
  />
</div>

          <div className="flex justify-between items-center mt-6">
            <span>AI Verification</span>
            <input
              type="checkbox"
              checked={aiReview}
              onChange={() => setAiReview(!aiReview)}
            />
          </div>

          <button
            onClick={handleScan}
            disabled={loading}
            className="w-full gradient-btn text-black font-bold py-3 rounded-xl mt-8"
          >
            {loading ? "Scanning..." : "INITIATE AUDIT"}
          </button>

        </div>

        <div className="glass p-8 col-span-2 shadow-2xl">

          <h2 className="text-xl font-semibold text-accent mb-8">
            Report Dashboard
          </h2>

          {!results && (
            <div className="h-48 flex items-center justify-center text-gray-500">
              Ready to audit. Target component required.
            </div>
          )}

          {results && results.findings && (
            <div className="space-y-6">
              {results.findings.map((f, i) => (
                <div key={i} className="bg-black/40 p-6 rounded-xl border border-white/10 space-y-4">

  <div>
    <h3 className="font-semibold text-accent text-lg">
      {f.activity}
    </h3>
    <p className="text-sm text-gray-400 mt-1">Path: {f.path}</p>
    <p className="text-sm text-gray-400">
      Query Param: {f.query_params?.join(", ")}
    </p>
    <p className="text-sm text-gray-400 mt-1">
      Level: {f.level}
    </p>
  </div>

  {/* ADB PoC Section */}
  {f.pocs && (
    <div className="bg-black/60 p-4 rounded-lg border border-accent/30">
      <p className="text-accent text-sm mb-2">ADB Exploit PoC:</p>
      {f.pocs.map((poc, idx) => (
        <pre
          key={idx}
          className="text-green-400 text-xs whitespace-pre-wrap mb-2"
        >
{poc}
        </pre>
      ))}
    </div>
  )}

  {/* AI Verdict Section */}
  {f.ai_review && (
    <div className="bg-accent/5 p-5 rounded-xl border border-accent/40 
                    shadow-[0_0_20px_rgba(0,255,198,0.15)]">
      <div className="flex items-center mb-3">
        <span className="text-accent text-lg mr-2">🧠</span>
        <p className="text-accent font-semibold">AI Security Analysis</p>
      </div>

      <div className="text-sm text-gray-300 whitespace-pre-wrap 
                      max-h-40 overflow-y-auto">
        {f.ai_review}
      </div>
    </div>
  )}

                </div>
              ))}
            </div>
          )}

        </div>

      </div>

      <div className="glass mt-12 p-6 shadow-xl">
        <h2 className="text-accent mb-4">Scan Summary</h2>
        <pre className="text-green-400 text-sm whitespace-pre-wrap">
{summary}
        </pre>
      </div>

    </div>
  );
}
