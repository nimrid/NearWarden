import puppeteer from 'puppeteer';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

const FPS = 15;
const WIDTH = 1920;
const HEIGHT = 1080;

const manifest = JSON.parse(fs.readFileSync('demo_video/audio/manifest.json', 'utf8'));

function easeInOutCubic(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

async function setupPage(browser) {
  const page = await browser.newPage();
  page.on('dialog', async (dialog) => {
    try { await dialog.accept(); } catch(e) {}
  });
  await page.setViewport({ width: WIDTH, height: HEIGHT });
  await page.goto('http://localhost:3000', { waitUntil: 'networkidle0' });

  // Inject virtual cursor and lower-third styles
  await page.evaluate(() => {
    window.__isAutomatedDemo = true;
    if (typeof state !== 'undefined') {
      state.registeredPasskey = { id: 'touch_id_supervisor_p256', type: 'PLATFORM_TOUCH_ID' };
    }
    // 1. Virtual cursor
    const cursor = document.createElement('div');
    cursor.id = 'v-cursor';
    cursor.innerHTML = `
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" style="filter: drop-shadow(0 2px 8px rgba(0,236,151,0.5));">
        <path d="M4 4l7 17 2.5-6.5L20 12 4 4z" fill="#00ec97" stroke="#000" stroke-width="1.5"/>
      </svg>
      <div id="v-click-ripple" style="position: absolute; top: 0; left: 0; width: 30px; height: 30px; border-radius: 50%; border: 2px solid #00ec97; opacity: 0; transform: scale(0.5); pointer-events: none; transition: transform 0.3s ease-out, opacity 0.3s ease-out;"></div>
    `;
    cursor.style.position = 'fixed';
    cursor.style.top = '0px';
    cursor.style.left = '0px';
    cursor.style.zIndex = '999999';
    cursor.style.pointerEvents = 'none';
    cursor.style.transform = 'translate(-100px, -100px)';
    document.body.appendChild(cursor);

    // 2. Lower-third badge
    const badge = document.createElement('div');
    badge.id = 'v-lower-third';
    badge.style.position = 'fixed';
    badge.style.bottom = '36px';
    badge.style.left = '40px';
    badge.style.zIndex = '999990';
    badge.style.background = 'rgba(8, 12, 22, 0.92)';
    badge.style.border = '1px solid rgba(0, 236, 151, 0.4)';
    badge.style.borderLeft = '4px solid #00ec97';
    badge.style.backdropFilter = 'blur(16px)';
    badge.style.borderRadius = '8px';
    badge.style.padding = '12px 22px';
    badge.style.boxShadow = '0 12px 40px rgba(0,0,0,0.7), 0 0 20px rgba(0,236,151,0.15)';
    badge.style.fontFamily = 'Inter, -apple-system, sans-serif';
    badge.style.display = 'flex';
    badge.style.alignItems = 'center';
    badge.style.gap = '16px';
    badge.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    badge.style.opacity = '0';
    badge.style.transform = 'translateY(20px)';
    badge.innerHTML = `
      <div style="width: 12px; height: 12px; border-radius: 50%; background: #00ec97; box-shadow: 0 0 12px #00ec97;"></div>
      <div>
        <div id="v-badge-cat" style="font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #8b949e; font-weight: 700;"></div>
        <div id="v-badge-text" style="font-size: 16px; color: #f0f6fc; font-weight: 700; margin-top: 2px;"></div>
      </div>
    `;
    document.body.appendChild(badge);

    // 3. Intro / Outro full screen overlay container
    const overlay = document.createElement('div');
    overlay.id = 'v-slide-overlay';
    overlay.style.position = 'fixed';
    overlay.style.inset = '0';
    overlay.style.zIndex = '999998';
    overlay.style.background = 'radial-gradient(ellipse at center, rgba(13,20,38,0.98) 0%, rgba(5,8,16,1.0) 100%)';
    overlay.style.display = 'none';
    overlay.style.flexDirection = 'column';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.fontFamily = 'Inter, -apple-system, sans-serif';
    overlay.style.color = '#fff';
    overlay.style.textAlign = 'center';
    document.body.appendChild(overlay);

    window.__cursorX = 960;
    window.__cursorY = 540;
  });

  return page;
}

async function setLowerThird(page, cat, text) {
  await page.evaluate((c, t) => {
    const badge = document.getElementById('v-lower-third');
    const catEl = document.getElementById('v-badge-cat');
    const textEl = document.getElementById('v-badge-text');
    if (!c && !t) {
      badge.style.opacity = '0';
      badge.style.transform = 'translateY(20px)';
      return;
    }
    catEl.textContent = c;
    textEl.textContent = t;
    badge.style.opacity = '1';
    badge.style.transform = 'translateY(0)';
  }, cat, text);
}

async function getElementCenter(page, selector) {
  return await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  }, selector);
}

async function captureFrames(page, frameDir, totalFrames, updateFn) {
  fs.mkdirSync(frameDir, { recursive: true });
  for (let f = 0; f < totalFrames; f++) {
    const progress = f / totalFrames;
    if (updateFn) await updateFn(f, progress);
    const framePath = path.join(frameDir, `frame_${String(f).padStart(5, '0')}.jpg`);
    await page.screenshot({ path: framePath, type: 'jpeg', quality: 85 });
  }
}

// ---------------------------------------------------------------------------
// SCENE 1: The Vulnerability & Threat Matrix
// ---------------------------------------------------------------------------
async function recordScene1(browser, manifestItem) {
  const page = await setupPage(browser);
  const totalFrames = Math.round(manifestItem.duration * FPS);
  const frameDir = `demo_video/raw_frames/scene1`;
  console.log(`\nRecording Scene 1 (${manifestItem.duration}s, ${totalFrames} frames)...`);

  // Start with Intro Title Card for first 4.5s
  await page.evaluate(() => {
    const overlay = document.getElementById('v-slide-overlay');
    overlay.style.display = 'flex';
    overlay.innerHTML = `
      <div style="max-width: 900px; padding: 40px; animation: fadeIn 0.6s ease-out;">
        <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(0,236,151,0.12); border: 1px solid rgba(0,236,151,0.4); padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 700; color: #00ec97; letter-spacing: 1px; margin-bottom: 24px;">
          <span>●</span> NEAR HACKATHON 2026 • AI AGENT SECURITY TRACK
        </div>
        <h1 style="font-size: 64px; font-weight: 800; letter-spacing: -1.5px; margin: 0 0 16px 0; background: linear-gradient(135deg, #ffffff 30%, #00ec97 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
          AgentGuard
        </h1>
        <p style="font-size: 24px; color: #8b949e; margin: 0 0 36px 0; line-height: 1.4;">
          Programmable AI Firewall, Spending Policy Engine &amp; Sandboxed Vault on NEAR Protocol
        </p>
        <div style="display: flex; justify-content: center; gap: 20px; font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #c9d1d9;">
          <div style="background: rgba(255,255,255,0.05); padding: 10px 18px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.1);">Vault: <span style="color: #00ec97;">longdata4360.testnet</span></div>
          <div style="background: rgba(255,255,255,0.05); padding: 10px 18px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.1);">Security: <span style="color: #00ec97;">Intel TDX + Scoped FCKs</span></div>
        </div>
      </div>
    `;
  });

  const introFrames = Math.round(4.5 * FPS);

  await captureFrames(page, frameDir, totalFrames, async (f, progress) => {
    // Phase 1: Intro slide
    if (f < introFrames) {
      return;
    }
    // Phase 2: Fade out overlay, reveal landing page
    if (f === introFrames) {
      await page.evaluate(() => {
        document.getElementById('v-slide-overlay').style.display = 'none';
      });
      await setLowerThird(page, 'THE FATAL FLAW', 'Full Access Keys (FAKs) Let Injected Agents Drain 100% of Treasury');
    }

    // Phase 3: Smooth scroll to vulnerabilities section
    if (f >= introFrames && f < introFrames + 75) {
      const p = (f - introFrames) / 75;
      const scrollY = easeInOutCubic(p) * 620;
      await page.evaluate((y) => window.scrollTo(0, y), scrollY);
    }

    // Phase 4: Move cursor to inspect vulnerability cards
    if (f >= introFrames + 75) {
      const p = (f - (introFrames + 75)) / (totalFrames - (introFrames + 75));
      const curX = 600 + easeInOutCubic(p) * 600;
      const curY = 480 + Math.sin(p * Math.PI * 2) * 50;
      await page.evaluate((x, y) => {
        const c = document.getElementById('v-cursor');
        c.style.transform = `translate(${x}px, ${y}px)`;
      }, curX, curY);
    }
  });

  await page.close();
  console.log(`Scene 1 finished.`);
}

// ---------------------------------------------------------------------------
// SCENE 2: Introducing AgentGuard & Architecture
// ---------------------------------------------------------------------------
async function recordScene2(browser, manifestItem) {
  const page = await setupPage(browser);
  const totalFrames = Math.round(manifestItem.duration * FPS);
  const frameDir = `demo_video/raw_frames/scene2`;
  console.log(`\nRecording Scene 2 (${manifestItem.duration}s, ${totalFrames} frames)...`);

  await setLowerThird(page, '3-LAYER DEFENSE ARCHITECTURE', 'Pre-Flight AI Firewall • On-Chain Vault • OutLayer Intel TDX TEE');

  // Scroll to architecture section
  await page.evaluate(() => {
    document.getElementById('architecture')?.scrollIntoView({ behavior: 'instant' });
  });

  await captureFrames(page, frameDir, totalFrames, async (f, progress) => {
    // Move cursor across Layer 1 -> Layer 2 -> Layer 3
    if (progress < 0.35) {
      const p = progress / 0.35;
      const curX = 350 + easeInOutCubic(p) * 150;
      const curY = 420;
      await page.evaluate((x, y) => {
        document.getElementById('v-cursor').style.transform = `translate(${x}px, ${y}px)`;
      }, curX, curY);
    } else if (progress < 0.65) {
      const p = (progress - 0.35) / 0.30;
      const curX = 750 + easeInOutCubic(p) * 150;
      const curY = 420;
      await page.evaluate((x, y) => {
        document.getElementById('v-cursor').style.transform = `translate(${x}px, ${y}px)`;
      }, curX, curY);
    } else {
      // Scroll to SDK integration and click tabs
      const p = (progress - 0.65) / 0.35;
      if (p < 0.2) {
        await page.evaluate(() => {
          document.getElementById('sdk-integration')?.scrollIntoView({ behavior: 'smooth' });
        });
      } else if (p < 0.5) {
        await page.evaluate(() => window.switchSdkTab('sdk-eliza'));
      } else {
        await page.evaluate(() => window.switchSdkTab('sdk-nearai'));
      }
    }
  });

  await page.close();
  console.log(`Scene 2 finished.`);
}

// ---------------------------------------------------------------------------
// SCENE 3: Live Demo: Autonomous Micro-Swap
// ---------------------------------------------------------------------------
async function recordScene3(browser, manifestItem) {
  const page = await setupPage(browser);
  const totalFrames = Math.round(manifestItem.duration * FPS);
  const frameDir = `demo_video/raw_frames/scene3`;
  console.log(`\nRecording Scene 3 (${manifestItem.duration}s, ${totalFrames} frames)...`);

  await page.evaluate(() => {
    window.scrollTo(0, 0);
    window.loadHeroScenario(1);
  });
  await setLowerThird(page, 'LIVE DEMO • SCENARIO 01', 'Authorized Micro-Swap: 0.5 NEAR to USDC via NEAR Intents');

  await captureFrames(page, frameDir, totalFrames, async (f, progress) => {
    // 0% - 30%: Cursor moves to "▶ Run Firewall Inspection"
    if (progress < 0.30) {
      const p = progress / 0.30;
      const btnPos = await getElementCenter(page, '#btn-hero-execute');
      if (btnPos) {
        const curX = 800 + (btnPos.x - 800) * easeInOutCubic(p);
        const curY = 300 + (btnPos.y - 300) * easeInOutCubic(p);
        await page.evaluate((x, y) => {
          document.getElementById('v-cursor').style.transform = `translate(${x}px, ${y}px)`;
        }, curX, curY);
      }
    } else if (progress >= 0.30 && progress < 0.35) {
      // Trigger execution & click animation
      await page.evaluate(() => {
        window.runHeroInspection();
        const ripple = document.getElementById('v-click-ripple');
        ripple.style.opacity = '1';
        ripple.style.transform = 'scale(1.5)';
        setTimeout(() => {
          ripple.style.opacity = '0';
          ripple.style.transform = 'scale(0.5)';
        }, 200);
      });
    } else {
      // 35% - 100%: Inspect output (200 ALLOWED, Ed25519 Verified, Threat 0/100)
      const p = (progress - 0.35) / 0.65;
      const curX = 1400 + Math.sin(p * Math.PI) * 40;
      const curY = 480 + p * 80;
      await page.evaluate((x, y) => {
        document.getElementById('v-cursor').style.transform = `translate(${x}px, ${y}px)`;
      }, curX, curY);
    }
  });

  await page.close();
  console.log(`Scene 3 finished.`);
}

// ---------------------------------------------------------------------------
// SCENE 4: Live Demo: Prompt Injection & Treasury Drainage Defense
// ---------------------------------------------------------------------------
async function recordScene4(browser, manifestItem) {
  const page = await setupPage(browser);
  const totalFrames = Math.round(manifestItem.duration * FPS);
  const frameDir = `demo_video/raw_frames/scene4`;
  console.log(`\nRecording Scene 4 (${manifestItem.duration}s, ${totalFrames} frames)...`);

  await page.evaluate(() => {
    window.scrollTo(0, 0);
  });
  await setLowerThird(page, 'LIVE DEMO • SCENARIO 02', 'Adversarial Prompt Injection: Intercepted in <10ms Before On-Chain Gas');

  await captureFrames(page, frameDir, totalFrames, async (f, progress) => {
    // 0% - 20%: Cursor moves to "Prompt Injection" pill and clicks it
    if (progress < 0.20) {
      const p = progress / 0.20;
      const pillPos = await getElementCenter(page, '.s-pill:nth-child(2)');
      if (pillPos) {
        const curX = 1200 + (pillPos.x - 1200) * easeInOutCubic(p);
        const curY = 400 + (pillPos.y - 400) * easeInOutCubic(p);
        await page.evaluate((x, y) => {
          document.getElementById('v-cursor').style.transform = `translate(${x}px, ${y}px)`;
        }, curX, curY);
      }
    } else if (progress >= 0.20 && progress < 0.25) {
      await page.evaluate(() => {
        window.loadHeroScenario(2);
      });
    } else if (progress >= 0.25 && progress < 0.40) {
      // Move to "▶ Run Firewall Inspection"
      const p = (progress - 0.25) / 0.15;
      const btnPos = await getElementCenter(page, '#btn-hero-execute');
      if (btnPos) {
        const pillPos = await getElementCenter(page, '.s-pill:nth-child(2)');
        const startX = pillPos ? pillPos.x : 1300;
        const startY = pillPos ? pillPos.y : 220;
        const curX = startX + (btnPos.x - startX) * easeInOutCubic(p);
        const curY = startY + (btnPos.y - startY) * easeInOutCubic(p);
        await page.evaluate((x, y) => {
          document.getElementById('v-cursor').style.transform = `translate(${x}px, ${y}px)`;
        }, curX, curY);
      }
    } else if (progress >= 0.40 && progress < 0.45) {
      // Click Run Firewall Inspection
      await page.evaluate(() => {
        window.runHeroInspection();
      });
    } else {
      // Highlighting red 403 BLOCKED and 95/100 Threat Score
      const p = (progress - 0.45) / 0.55;
      const curX = 1450 + Math.sin(p * Math.PI * 2) * 60;
      const curY = 420 + easeInOutCubic(p) * 60;
      await page.evaluate((x, y) => {
        document.getElementById('v-cursor').style.transform = `translate(${x}px, ${y}px)`;
      }, curX, curY);
    }
  });

  await page.close();
  console.log(`Scene 4 finished.`);
}

// ---------------------------------------------------------------------------
// SCENE 5: Live Demo: Policy Console & Biometric Passkey Escalation
// ---------------------------------------------------------------------------
async function recordScene5(browser, manifestItem) {
  const page = await setupPage(browser);
  const totalFrames = Math.round(manifestItem.duration * FPS);
  const frameDir = `demo_video/raw_frames/scene5`;
  console.log(`\nRecording Scene 5 (${manifestItem.duration}s, ${totalFrames} frames)...`);

  // Switch to WAF Console
  await page.evaluate(() => {
    window.switchView('console');
    window.syncOnChainState();
  });
  await setLowerThird(page, 'ENTERPRISE WAF CONSOLE', 'Live RPC Sync • Spending Quotas • Biometric WebAuthn Passkeys');

  const evalTabFrame = Math.round(3.0 * FPS);
  const runTestsFrame = Math.round(6.0 * FPS);
  const multisigTabFrame = Math.round(15.0 * FPS);
  const approveFrame = Math.round(21.0 * FPS);

  await captureFrames(page, frameDir, totalFrames, async (f, progress) => {
    if (f === evalTabFrame) {
      await page.evaluate(() => {
        document.querySelector('[data-tab="tab-eval"]')?.click();
      });
    } else if (f === runTestsFrame) {
      await page.evaluate(() => {
        document.getElementById('btn-run-all-tests-main')?.click();
      });
    } else if (f === multisigTabFrame) {
      await page.evaluate(() => {
        document.querySelector('[data-tab="tab-multisig"]')?.click();
      });
      await setLowerThird(page, 'HUMAN-IN-THE-LOOP MULTI-SIG', 'Apple Touch ID / NIST P-256 Passkey Approves High-Value Escalations');
    } else if (f === approveFrame) {
      await page.evaluate(() => {
        window.approveActionWithPasskey(101);
      });
    }
  });

  await page.close();
  console.log(`Scene 5 finished.`);
}

// ---------------------------------------------------------------------------
// SCENE 6: Live Testnet Verification, Chain Signatures & Closing
// ---------------------------------------------------------------------------
async function recordScene6(browser, manifestItem) {
  const page = await setupPage(browser);
  const totalFrames = Math.round(manifestItem.duration * FPS);
  const frameDir = `demo_video/raw_frames/scene6`;
  console.log(`\nRecording Scene 6 (${manifestItem.duration}s, ${totalFrames} frames)...`);

  await page.evaluate(() => {
    window.switchView('console');
    document.querySelector('[data-tab="tab-keys"]')?.click();
  });
  await setLowerThird(page, 'ON-CHAIN NEAR TESTNET PROOF', 'Vault: longdata4360.testnet • Multisig Owner: guard.longdata4360.testnet');

  const docsTabFrame = Math.round(8.0 * FPS);
  const outroStartFrame = Math.round((manifestItem.duration - 8.5) * FPS);

  await captureFrames(page, frameDir, totalFrames, async (f, progress) => {
    if (f === docsTabFrame) {
      await page.evaluate(() => {
        document.querySelector('[data-tab="tab-docs"]')?.click();
      });
    } else if (f === outroStartFrame) {
      // Render Grand Finale Outro Slide once
      await setLowerThird(page, null, null);
      await page.evaluate(() => {
        const overlay = document.getElementById('v-slide-overlay');
        overlay.style.display = 'flex';
        overlay.innerHTML = `
          <div style="max-width: 950px; padding: 40px; animation: fadeIn 0.6s ease-out;">
            <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(0,236,151,0.15); border: 1px solid rgba(0,236,151,0.5); padding: 8px 20px; border-radius: 24px; font-size: 14px; font-weight: 700; color: #00ec97; letter-spacing: 1.5px; margin-bottom: 24px;">
              <span>🛡️</span> AGENTGUARD — NEAR HACKATHON 2026
            </div>
            <h1 style="font-size: 56px; font-weight: 900; letter-spacing: -1.5px; margin: 0 0 20px 0; color: #ffffff;">
              Give AI Money, Without Giving It The Keys To Everything.
            </h1>
            <p style="font-size: 20px; color: #8b949e; margin: 0 0 36px 0; line-height: 1.5;">
              Programmable WAF • OutLayer Intel TDX TEE • NIST P-256 Passkeys • Scoped FCKs • NEAR Chain Signatures
            </p>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 36px; text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 13px;">
              <div style="background: rgba(255,255,255,0.04); padding: 14px 18px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08);">
                <div style="color: #8b949e; font-size: 11px; margin-bottom: 4px;">TESTNET VAULT</div>
                <div style="color: #00ec97; font-weight: 600;">longdata4360.testnet</div>
              </div>
              <div style="background: rgba(255,255,255,0.04); padding: 14px 18px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08);">
                <div style="color: #8b949e; font-size: 11px; margin-bottom: 4px;">MULTISIG GOVERNANCE</div>
                <div style="color: #00ec97; font-weight: 600;">guard.longdata4360.testnet</div>
              </div>
              <div style="background: rgba(255,255,255,0.04); padding: 14px 18px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.08);">
                <div style="color: #8b949e; font-size: 11px; margin-bottom: 4px;">OUTLAYER HARDWARE TEE</div>
                <div style="color: #00ec97; font-weight: 600;">Intel TDX Verified</div>
              </div>
            </div>
            <div style="font-size: 16px; color: #c9d1d9;">
              Open Source Repository: <span style="color: #58a6ff; font-family: 'JetBrains Mono', monospace; font-weight: 700;">github.com/nimrid/agentGuard</span>
            </div>
          </div>
        `;
      });
    }
  });

  await page.close();
  console.log(`Scene 6 finished.`);
}

// ---------------------------------------------------------------------------
// MAIN RECORDING & ENCODING ORCHESTRATOR
// ---------------------------------------------------------------------------
async function main() {
  console.log('================================================================================');
  console.log('             AGENTGUARD SILICON VALLEY DEMO VIDEO RENDERER                     ');
  console.log('================================================================================');

  const browser = await puppeteer.launch({
    executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    headless: 'new',
    protocolTimeout: 300000,
    defaultViewport: { width: WIDTH, height: HEIGHT },
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const sceneFns = [recordScene1, recordScene2, recordScene3, recordScene4, recordScene5, recordScene6];

  for (let i = 0; i < manifest.length; i++) {
    const item = manifest[i];
    const sceneMp4 = `demo_video/${item.id}.mp4`;

    if (fs.existsSync(sceneMp4) && fs.statSync(sceneMp4).size > 100000) {
      console.log(`\nScene ${item.id} (${sceneMp4}) already exists. Skipping capture.`);
      continue;
    }

    await sceneFns[i](browser, item);

    // Encode individual scene with its narration track
    const frameDir = `demo_video/raw_frames/${item.id}`;
    const audioFile = item.file;

    console.log(`Encoding ${sceneMp4}...`);
    const cmd = [
      'ffmpeg', '-y',
      '-framerate', String(FPS),
      '-i', `${frameDir}/frame_%05d.jpg`,
      '-i', audioFile,
      '-c:v', 'libx264',
      '-preset', 'fast',
      '-crf', '19',
      '-pix_fmt', 'yuv420p',
      '-c:a', 'aac',
      '-b:a', '192k',
      '-shortest',
      sceneMp4
    ];
    execSync(cmd.join(' '), { stdio: 'inherit' });
  }

  await browser.close();

  // Concatenate all 6 scenes
  console.log('\nConcatenating all 6 scene video files...');
  const concatList = manifest.map(m => `file '${m.id}.mp4'`).join('\n');
  fs.writeFileSync('demo_video/concat_list.txt', concatList);

  execSync('ffmpeg -y -f concat -safe 0 -i demo_video/concat_list.txt -c copy demo_video/video_raw.mp4', { stdio: 'inherit' });

  // Mix background music under the narration
  console.log('\nMixing ambient background music track (-22dB)...');
  const finalOutput = 'demo_video/AgentGuard_NEAR_Hackathon_Demo.mp4';
  const mixCmd = [
    'ffmpeg', '-y',
    '-i', 'demo_video/video_raw.mp4',
    '-i', 'demo_video/audio/bgm.wav',
    '-filter_complex', '"[0:a]volume=1.0[v];[1:a]volume=0.14[bgm];[v][bgm]amix=inputs=2:duration=first[aout]"',
    '-map', '0:v',
    '-map', '"[aout]"',
    '-c:v', 'copy',
    '-c:a', 'aac',
    '-b:a', '256k',
    finalOutput
  ];
  execSync(mixCmd.join(' '), { stdio: 'inherit' });

  const stats = fs.statSync(finalOutput);
  console.log('\n================================================================================');
  console.log('             DEMO VIDEO GENERATION COMPLETE!                                   ');
  console.log(`  File: ${finalOutput} (${(stats.size / (1024 * 1024)).toFixed(2)} MB)`);
  console.log('================================================================================\n');
}

main().catch(err => {
  console.error('Recording error:', err);
  process.exit(1);
});

