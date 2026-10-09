(() => {
  "use strict";

  const API_URL = (window.ITL_CONFIG && window.ITL_CONFIG.API_URL) || "/check";

  // The verdict badge is drawn from Layer 1's verdict, never from AI text,
  // so these labels are translated here rather than by the model.
  const LABELS = {
    en: { dont_click: "DON'T CLICK", careful: "BE CAREFUL", looks_ok: "LOOKS OK" },
    es: { dont_click: "NO HAGAS CLIC", careful: "TEN CUIDADO", looks_ok: "PARECE BIEN" },
    zh: { dont_click: "不要点击", careful: "要小心", looks_ok: "看起来没问题" },
    hi: { dont_click: "क्लिक न करें", careful: "सावधान रहें", looks_ok: "ठीक लगता है" },
    vi: { dont_click: "ĐỪNG BẤM", careful: "HÃY CẨN THẬN", looks_ok: "CÓ VẺ ỔN" },
    ko: { dont_click: "누르지 마세요", careful: "조심하세요", looks_ok: "괜찮아 보여요" },
    tl: { dont_click: "HUWAG I-CLICK", careful: "MAG-INGAT", looks_ok: "MUKHANG OK" },
    pt: { dont_click: "NÃO CLIQUE", careful: "CUIDADO", looks_ok: "PARECE OK" },
  };
  // Button and heading text around the answer, so the whole result card
  // reads in one language.
  const UI = {
    en: { todo: "What to do", speak: "🔊 Read it to me", stop: "⏹ Stop", share: "💬 Send to family", clues: "Show me the clues" },
    es: { todo: "Qué hacer", speak: "🔊 Léemelo", stop: "⏹ Parar", share: "💬 Enviar a la familia", clues: "Ver las pistas" },
    zh: { todo: "怎么做", speak: "🔊 读给我听", stop: "⏹ 停止", share: "💬 发给家人", clues: "查看线索" },
    hi: { todo: "क्या करें", speak: "🔊 पढ़कर सुनाओ", stop: "⏹ रोकें", share: "💬 परिवार को भेजें", clues: "सुराग दिखाएं" },
    vi: { todo: "Nên làm gì", speak: "🔊 Đọc cho tôi nghe", stop: "⏹ Dừng", share: "💬 Gửi cho gia đình", clues: "Xem dấu hiệu" },
    ko: { todo: "이렇게 하세요", speak: "🔊 읽어 주세요", stop: "⏹ 멈추기", share: "💬 가족에게 보내기", clues: "단서 보기" },
    tl: { todo: "Ano ang gagawin", speak: "🔊 Basahin mo sa akin", stop: "⏹ Itigil", share: "💬 Ipadala sa pamilya", clues: "Ipakita ang mga palatandaan" },
    pt: { todo: "O que fazer", speak: "🔊 Leia para mim", stop: "⏹ Parar", share: "💬 Enviar para a família", clues: "Mostrar as pistas" },
  };
  const ui = () => UI[(last && UI[last.language]) ? last.language : "en"];
  const ICONS = { dont_click: "🛑", careful: "⚠️", looks_ok: "✅" };
  const SPEECH_LANG = { en: "en-US", es: "es-ES", zh: "zh-CN", hi: "hi-IN", vi: "vi-VN", ko: "ko-KR", tl: "fil-PH", pt: "pt-BR" };

  const SAMPLES = {
    toll: "E-ZPass: You have an unpaid toll balance of $4.15. To avoid a late fee of $50.00, pay within 24 hours: https://ezpass-tollpay.top/pay",
    mom: "Hi Mom, this is my new number, I dropped my phone in the toilet. Can you help me pay a bill today? I'll pay you back tomorrow. Don't tell dad yet.",
    paypal: "Dear Customer,\n\nWe noticed unusual activity on your PayPal account. Your account has been limited. Please verify your account within 48 hours to avoid suspension.\n\nhttps://www.paypa1-security.com/signin\n\nThank you,\nPayPal Security",
    amazon: "Hello, your Amazon order of \"Anker USB-C Charger\" has shipped. Track your package: https://www.amazon.com/progress-tracker/package?orderId=113-4472918",
  };

  const $ = (id) => document.getElementById(id);
  const form = $("form"), msg = $("message"), go = $("go"), clear = $("clear");
  const langSel = $("lang");
  let last = null;

  // Remember the language between visits. Storage can be blocked; that's fine.
  try {
    const saved = localStorage.getItem("itl-lang");
    if (saved && LABELS[saved]) langSel.value = saved;
  } catch (_) {}
  langSel.addEventListener("change", () => {
    try { localStorage.setItem("itl-lang", langSel.value); } catch (_) {}
    if (last && msg.value.trim()) run();
  });

  document.querySelectorAll("[data-sample]").forEach((b) =>
    b.addEventListener("click", () => {
      msg.value = SAMPLES[b.dataset.sample];
      run();
    })
  );

  form.addEventListener("submit", (e) => { e.preventDefault(); run(); });

  clear.addEventListener("click", () => {
    msg.value = "";
    $("result").hidden = true;
    $("error").hidden = true;
    clear.hidden = true;
    stopSpeaking();
    msg.focus();
  });

  async function run() {
    const text = msg.value;
    $("error").hidden = true;
    if (!text.trim()) {
      showError("Paste the message you got first, then tap Check it.");
      return;
    }
    stopSpeaking();
    go.disabled = true;
    go.textContent = "Checking…";
    try {
      const res = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, language: langSel.value }),
      });
      const data = await res.json().catch(() => ({}));
      if (!data.ok) {
        showError(data.error || "Something went wrong on my end. Please try again in a moment.");
        return;
      }
      render(data);
    } catch (_) {
      showError("I couldn't reach the checker. Check your internet connection and try again.");
    } finally {
      go.disabled = false;
      go.textContent = "Check it";
    }
  }

  function render(data) {
    last = data;
    const lang = LABELS[data.language] ? data.language : "en";
    const v = data.verdict;
    const box = $("verdict");
    box.className = "verdict " + v;
    $("verdict-icon").textContent = ICONS[v];
    $("verdict-label").textContent = LABELS[lang][v];
    $("headline").textContent = data.explanation.headline;
    $("why").textContent = data.explanation.why;
    $("why").hidden = !data.explanation.why;
    $("do-this").textContent = data.explanation.do_this;
    $("todo-h").textContent = ui().todo;
    $("speak").textContent = ui().speak;
    $("share").textContent = ui().share;
    $("clues-h").textContent = ui().clues;

    renderExpanded(data.expanded || []);

    const ul = $("clues");
    ul.replaceChildren();
    if (!data.findings.length) {
      const li = document.createElement("li");
      li.textContent = "No warning signs found: no fake links, no pressure, no requests for money, passwords or codes.";
      ul.appendChild(li);
    }
    for (const f of data.findings) {
      const li = document.createElement("li");
      const sev = document.createElement("span");
      sev.className = "sev " + f.severity;
      sev.textContent = f.severity;
      const ev = document.createElement("span");
      ev.className = "ev";
      ev.textContent = "“" + f.evidence + "”";
      li.append(sev, document.createTextNode(f.title), ev);
      ul.appendChild(li);
    }
    $("ai-note").textContent = data.ai
      ? "Explanation written by Amazon Bedrock. The verdict comes from fixed safety rules the AI cannot change."
      : "Explanation from built-in rules (the AI helper was busy). The verdict is the same either way.";

    $("result").hidden = false;
    clear.hidden = false;
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Short links (bit.ly etc.): show where they really go. Built with
  // textContent only; every address arrives already defanged.
  function renderExpanded(items) {
    const ul = $("expanded");
    ul.replaceChildren();
    for (const e of items) {
      const li = document.createElement("li");
      const short = document.createElement("code");
      short.textContent = e.short;
      if (e.status === "ok") {
        const dest = document.createElement("code");
        dest.textContent = e.final;
        li.append("🔗 Short link ", short, " really goes to ", dest);
      } else if (e.status === "blocked") {
        li.append("⛔ Short link ", short, " has been flagged as harmful by the link-shortening company.");
      } else if (e.status === "dead") {
        li.append("🔗 Short link ", short, " no longer works.");
      } else {
        li.append("🔗 Couldn't check where short link ", short, " goes.");
      }
      ul.appendChild(li);
    }
    ul.hidden = items.length === 0;
  }

  function showError(text) {
    const el = $("error");
    el.textContent = text;
    el.hidden = false;
  }

  // ---- Read it to me ------------------------------------------------------
  const speakBtn = $("speak");
  if (!("speechSynthesis" in window)) speakBtn.hidden = true;

  function stopSpeaking() {
    if ("speechSynthesis" in window) speechSynthesis.cancel();
    speakBtn.textContent = ui().speak;
  }

  speakBtn.addEventListener("click", () => {
    if (!last) return;
    if (speechSynthesis.speaking) { stopSpeaking(); return; }
    const lang = LABELS[last.language] ? last.language : "en";
    const e = last.explanation;
    const u = new SpeechSynthesisUtterance(
      [LABELS[lang][last.verdict] + ".", e.headline, e.why, e.do_this].join(" ").replace(/\[\.\]/g, " dot ")
    );
    u.lang = SPEECH_LANG[lang] || "en-US";
    u.rate = 0.9;
    u.onend = stopSpeaking;
    speakBtn.textContent = ui().stop;
    speechSynthesis.speak(u);
  });

  // ---- Send to family -----------------------------------------------------
  $("share").addEventListener("click", async () => {
    if (!last) return;
    const lang = LABELS[last.language] ? last.language : "en";
    const text =
      `I checked a message with "Is This Legit?" and it says: ${ICONS[last.verdict]} ${LABELS[lang][last.verdict]}\n` +
      `${last.explanation.headline} ${last.explanation.why}\n` +
      `What to do: ${last.explanation.do_this}`;
    try {
      if (navigator.share) {
        await navigator.share({ text });
        return;
      }
      await navigator.clipboard.writeText(text);
      flash($("share"), "✅ Copied. Paste it in a text.");
    } catch (_) {
      /* user closed the share sheet */
    }
  });

  function flash(btn, text) {
    const old = btn.textContent;
    btn.textContent = text;
    setTimeout(() => (btn.textContent = old), 2500);
  }
})();
