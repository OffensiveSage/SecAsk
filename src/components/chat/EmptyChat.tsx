"use client";

const STARTER_SUGGESTIONS = [
	"What ATT&CK techniques use PowerShell?",
	"Show Sigma rules for lateral movement",
	"Does CVE-2024-3400 have detection coverage?",
	"Map NIST AC-2 account management controls",
	"Find authentication vulnerabilities in this code",
];

interface EmptyChatProps {
	owner: string;
	repo: string;
	onSelectSuggestion: (text: string) => void;
}

export function EmptyChat({ owner, repo, onSelectSuggestion }: EmptyChatProps) {
	return (
		<div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1, gap: 24, textAlign: "center", background: "transparent" }}>
			<div>
				<span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", display: "block", marginBottom: 12 }}>
					{owner}/{repo}
				</span>
				<h2 style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: "clamp(1.3rem, 3vw, 2rem)", color: "var(--ink-black)", letterSpacing: "-0.02em", margin: 0 }}>
					What do you want to know?
				</h2>
			</div>
			<div style={{ display: "flex", flexWrap: "wrap", gap: 10, justifyContent: "center", maxWidth: 560 }}>
				{STARTER_SUGGESTIONS.map(suggestion => (
					<button
						key={suggestion}
						onClick={() => onSelectSuggestion(suggestion)}
						style={{
							padding: "10px 16px",
							border: "2.5px solid var(--border-black)",
							background: "var(--bg-paper)",
							color: "var(--ink-black)",
							boxShadow: "var(--shadow-subtle)",
							cursor: "pointer",
							fontSize: "13px",
							fontFamily: "var(--font-sans)",
							transition: "transform 0.1s ease, box-shadow 0.1s ease",
						}}
						onMouseEnter={(e) => {
							(e.currentTarget as HTMLButtonElement).style.transform = "translate(-1px,-1px)";
							(e.currentTarget as HTMLButtonElement).style.boxShadow = "var(--shadow-layer-1)";
						}}
						onMouseLeave={(e) => {
							(e.currentTarget as HTMLButtonElement).style.transform = "";
							(e.currentTarget as HTMLButtonElement).style.boxShadow = "var(--shadow-subtle)";
						}}
					>
						{suggestion}
					</button>
				))}
			</div>
		</div>
	);
}
