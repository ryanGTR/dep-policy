# dep-policy — 第三方套件白名單（Policy as Code）

這個 repo 是 [`supply-chain-demo`](https://github.com/ryanGTR/supply-chain-demo) 用的
**唯一允許套件清單**的真實來源。App 的 CI 在 build 前比對宣告依賴 vs 這裡的 yaml，
不在清單的一律擋。

## 審核流程（GitHub-native）

要加套件 = 開 PR 改 `{maven,npm,nuget}-approved.yaml`：

1. PR 觸發 `dep-policy-review` workflow：
   - **lint**：yaml 結構 / 必填 `coord`
   - **OSV CVE 查**：對新增 coord 查漏洞，結果貼回 PR comment
   - **cooldown**：新版本須年滿 30 天（防剛上架的惡意套件），未過 → 擋
2. **CODEOWNERS 強制核可**（ruleset：Require review from Code Owners、禁 bypass）
3. merge → App build 重跑 → policy gate 放行

> GitHub 的 PR / CODEOWNERS / required reviews / audit log 本身就是審核紀錄，
> 不需要另一套簽核系統。CVE 是 informational（給人看、人決定）；cooldown 是 hard gate。

## 檔案

| 檔案 | 用途 |
|---|---|
| `maven-approved.yaml` / `npm-approved.yaml` / `nuget-approved.yaml` | 白名單（Maven / npm / NuGet）|
| `CODEOWNERS` | yaml 變更需 code owner 核可 |
| `.github/workflows/review.yml` | PR 自動審查（CVE + cooldown）|
| `scripts/cooldown-check.sh` / `recheck-approved.sh` | cooldown / 持續重掃 |

移植自 GitLab 版（`security-team/dep-policy`）。
