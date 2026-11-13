# Development

`rcs956`はRC-S956のフレーム、取引状態、RF設定、カードプロトコルを所有する。`no_std`と`alloc`で動作し、crate全体で`unsafe_code`を禁止する。crateが定義する`Transport`へ同期転送、pipe回復、単調時計、待機を委譲し、期限・待機時間とエラー時の状態遷移はcrateで決める。OSのデバイス列挙、USB backend、ドライバとの通信は`Transport`の実装側が所有する。

## ビルドと検証

リポジトリのルートで実行する。`no_std` 検証にはベアメタル向け Rust target が必要。

```powershell
cargo build --locked
cargo fmt --check
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features --config "build.rustdocflags=['-Dwarnings']"
cargo check --locked --lib --all-features --target x86_64-unknown-none
```

## 状態と失敗の契約

各操作の詳細な条件は定義側のrustdocが正本であり、ここではcrate全体に共通する契約だけを示す。

失敗した初期化を成功状態として公開しない。カードhandleはreaderの排他的borrowを保持し、選択・raw交換・認証の権限はそのborrowとRF状態より長く残らない。raw交換や認証へ移るとtyped handleは消費され、その前提は回復しない。

どの操作も自動で再送しない。例外はFALPの再送で、protocol自体が順序番号で重複を排除する欠落blockの再要求と、応答のない送信切替blockの再送だけを行う。送信前の拒否や準備失敗と、送信後の失敗を区別し、送信後の失敗ではカードへの効果が不明になり得るため、確認済みのprogressをerrorに残す。transport失敗後にはRF readinessが失効する。readerへの`initialize`は明示的な再同期であり、失敗したカード操作の再実行や結果照合ではない。

回復ではpipeの状態整理とhost ACKによる未完了commandの中断を行い、その後はresetだけを許可する。USB pipe resetだけをfirmware commandの中断として扱わない。中断前のカード操作の結果不明はcallerに残る。

`rf_off`や`finish`の失敗はcallerが観測する。DropはOS resourceの解放だけを担当する。

NDEFの書込みはメッセージを非公開にしてから本文を更新し、最後に公開する。失敗はその段階と確認済みbytes数を返すため、callerは再選択してタグの状態を確認してから回復操作を判断する。

## 検証境界

固定packet vectorはデバイスに送るフレームと応答の解釈を検証する。実機captureはUSBとRFの観測範囲を別途記録する。

NFC-A／Bの固定vectorはカード実機の成功証拠ではない。全firmware、全カードcommand／APDUの意味と副作用の成立は、固定vectorの検証対象に含めない。

## 外部実装へ委譲する責務

`felica-lite-s` featureは2-key TDESを`des`、MACの比較を`subtle`、鍵用バッファの消去を`zeroize`に委譲し、Lite-Sのプロトコル、MACの入力構成、session状態はcrateが所有する。`felica-standard-aes` featureはAESとCMACをRustCryptoへ委譲し、暗号フレームと取引番号はcrateが所有する。フレーム形式の参照は[FeliCa Card User's Manual (Unofficial Edition)](https://soltia48.github.io/felica-users-manual-unofficial/en/)のMutual Authentication and Secure Messaging Algorithms。どちらもカード鍵と認証ごとのCSPRNG challengeは呼出側が供給する。

`serde_json`は固定fixtureの読取にだけ使うdev dependencyで、通常のlibraryへ入れない。JSON parserとそのformatter／string処理の依存、およびCargo targetに基づくbuild scriptはtest buildのtrust surfaceとして扱う。
