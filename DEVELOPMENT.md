# Build and device validation

`rcs956`はフレーム、取引状態、RF設定、カードプロトコルを所有する。`no_std`と`alloc`で動作し、crate全体で`unsafe_code`を禁止する。Rustからは`rcs956::reader::Reader`などを使用する。coreが定義する`Transport`へ同期転送、pipe回復、単調時計、待機を委譲し、期限・待機時間とエラー時の状態遷移はcoreで決める。

## ビルドと検証

リポジトリのルートで実行する。既定のビルド対象は `rcs956`。core の `no_std` 検証にはベアメタル向け Rust target が必要。

```powershell
cargo build --locked
cargo fmt --all --check
cargo check --locked -p rcs956 --lib --target x86_64-unknown-none
```

ドライバのビルドには Windows SDK、UMDF の WDF ヘッダとライブラリを含む WDK、MSVC、LLVM の libclang が必要。[windows-drivers-rs の開発環境](https://github.com/microsoft/windows-drivers-rs#setup)を参照する。ドライバの feature は `usb` と `pcsc` のいずれか一つを選ぶ。`cargo build-usb` は USB ドライバと CLI をビルドする。

```powershell
cargo build-usb
cargo build-pcsc
cargo test --locked --workspace --features rcs956-driver/usb
cargo test --locked -p rcs956-driver --features pcsc
cargo clippy --locked --workspace --all-targets --features rcs956-driver/usb -- -D warnings
cargo clippy --locked -p rcs956-driver --all-targets --features pcsc -- -D warnings
cargo doc --locked --workspace --no-deps --features rcs956-driver/usb --config "build.rustdocflags=['-Dwarnings']"
```

Windows 11 向けの未署名パッケージは `driver/package.ps1` で生成する。`-Mode` でインストールするインターフェイスを指定する。WDK のコマンドプロンプトを使うか、`-WdkBin` に使用するバージョンの WDK の bin ディレクトリを渡す。スクリプトが出力したディレクトリに DLL、INF、カタログが揃う。インストール環境の署名要件を満たしたパッケージを使用する。

```powershell
./driver/package.ps1 -Mode usb
./driver/package.ps1 -Mode pcsc
```

## 実機検証ツール

[`tools/cli`](tools/cli)の`rcs956-cli`はUMDF 2のUSBモードを使う実機検証ツールで、実行ファイル名は`rcs956`。CLIの実行時はpackageを指定する。

```powershell
cargo run --locked -p rcs956-cli -- devices
cargo run --locked -p rcs956-cli -- probe
cargo run --locked -p rcs956-cli -- poll --type felica --system FFFF --request 1 --slots 0
cargo run --locked -p rcs956-cli -- poll --type a
cargo run --locked -p rcs956-cli -- poll --type b
cargo run --locked -p rcs956-cli -- read --system 88B4 --service 000B --blocks 0,1
```

read例のservice／systemは対象カードに存在するものを指定する。未確認のカードへ例の値をそのまま適用しない。`--path`は複数リーダーの中から対象のapplication interfaceを指定する。同じUSB functionの複数aliasは1台として扱い、使用可能なfunctionが1台なら登録pathのソート順で先頭を選ぶ。`--timeout-ms`はRF交換の有限待機値で、host応答待機には余裕時間を加える。`exchange --type a --data HEX`はカードcommand、`exchange --type b --data HEX`はISO-DEP APDUを送る。送信内容とカードへの効果はcallerが決める。FeliCaのreadは非暗号化読取だけを行う。application commandの自動再実行はしない。

## Windows のデバイスインターフェイス

両モードは USB ID `054C:02E1` と 64-byte Bulk IN／OUT を検査する。同じ USB function にインストールするドライバパッケージは一つ。CLI の `devices` は接続中のデバイスと、USB モードで開けるパスを表示する。

USB モードは単一のクライアントに USB 転送を許可する。reader の初期化、取引の回復、NDEF と各カードプロトコルはクライアントで動作する。ドライバは転送長とタイムアウトを検査して USB I/O を直列化する。アプリケーションコマンドをドライバ内で再実行しない。

PC/SC モードでは Smart Card Resource Manager が USB デバイスを NFC-A／NFC-B の ISO-DEP リーダーとして利用する。T=1 の ATR を生成し、WinSCard から最大262 bytesの APDU を選択中のカードに送る。カードの待機中は挿入と離脱をポーリングする。接続中のカードの離脱は APDU 交換の失敗、または電源解除後の再ポーリングで検出する。FeliCa とストレージカードの疑似 APDU は PC/SC モードの対象外。

```powershell
cargo run --locked -p rcs956-driver --features pcsc --example pcsc_probe -- list
cargo run --locked -p rcs956-driver --features pcsc --example pcsc_probe -- connect
```

`connect` は ATR を表示する。追加引数に16進 APDU を指定すると、選択したカードにそのコマンドを送る。

## 設定とカードsession

初期化はreset／host ACK、設定bank読取、checksum／model検査、register設定、RF offを順に行う。失敗した初期化を成功状態として公開しない。RF modeはprotocolと適用済みtimerを保持し、protocol変更時には対応する設定imageのtableを適用する。`4A`はFeliCaを212または424 kbps、NFC-A／Bを106 kbpsで1 target検出する。

NFC-AはUID（4／7／10 bytes）、SAK、optional ATSのTLとinterface byte境界を検査する。`TypeACard::into_raw`は型付き操作の権限を消費して、最大262 bytesの任意commandを許可する。raw交換はfragmentごとにreader statusを保持し、継続中は空の`40 target`による回収だけを許可する。`exchange --type a`は各fragmentを表示する。継続中にhandleを手放した場合や回収が失敗した場合は再初期化が必要。完了したraw交換の後は、新たな選択前にRFを切り、Type 2のセクター選択などのカード状態を解消する。`--type a-apdu`はSAKとATSでISO-DEP activationを確認して継続応答をまとめ、交換に失敗した場合は部分応答を返す。

NFC-Aの`40`交換では、要求待機を整数msへ切り上げ、`32 02 0B 0B code`の段階値へ変換する。RF応答待機は最大3280 msへ制限され、`1C`にはその実効待機を使う。host待機は実効待機に1秒を加える。成功したselectorとreader timerだけを保持し、同値の設定送信を省略する。RF offやtargetの再選択でselectorは失効しないが、reset／不確定な設定失敗では失効する。`TypeAExchangeError::Preparation`はカードcommand送信前の設定失敗を示し、再初期化を要求する。`Exchange`はカード交換段階の失敗を示し、原因に応じてカードへの効果が不明になり得る。

NFC-BはATQB／ATTRIBを検査し、ISO-DEP targetにAPDU交換を、その他のprotocolには`40`による最大63 bytesのカードコマンド交換を提供する。CLIではそれぞれ`--type b`と`--type b-frame`で選ぶ。`--b-profile`でreader設定imageのtable3（standard）またはtable5（alternate）を選び、`--afi`でApplication Family Identifierを指定する。既定はtable3とAFI wildcard。FSCIは0〜8、FWIは0〜14、CIDは0〜14を受理し、非zero CIDはカードの対応を必要とする。`--nad`はATQBで対応を示したカードに限り、送受信chainの先頭I-blockにnode addressを付ける。ISO-DEPの送信frameはカードのFSCと64-byte reader容量の小さい方に制限する。受信はRC-S956のoptional activation extensionのFSDI（省略時5）と64-byte容量の小さい方を上限とする。MBLIが非zeroの場合は`FSC × 2^(MBLI − 1)`のカードbuffer上限も送信前に検査し、zeroの場合は上限不明として扱う。CRCはreaderに委譲する。FeliCaの非暗号化読取とNFC-Bの個別block交換は`A0`を使う。

NFC-BのAPDU交換前には`32 02 0B 0B 10`と`1C 80 8F 01`を設定する。`32/02`の実効待機3280 msから`1C`を決め、blockごとのFWI／WTX待機は`A0`へ独立に指定する。WTXで`1C`は変更しない。成功したselectorとtimerは別々に保持し、再検出やprotocol切替でtimerが変わればAPDU前に再適用する。設定の途中で失敗した場合はapplication blockを送信せず再初期化を要求する。

NFC-BのISO-DEP sessionはblock番号、送受信chaining、R-block、WTXを処理する。空のINFを持つ継続I-blockも受理し、応答bytesを増やさずblock番号とframe数を進めてR-ACKを返す。application入力は1〜65535 bytes、応答は65536 bytes、RF callbackは2048回、WTXは32回、protocol再送は2回を上限とする。最低限の送信frame数だけでbudgetを超える入力は送信前に拒否する。初期block待機はATQBのFWIに基づく`330 us × 2^FWI`。WTXでは要求倍率を応答に返し、待機は倍率を掛けた値をFWI=14相当の上限に制限する。`--timeout-ms`は検出待機を指定し、NFC-Bの各block待機を上書きしない。

APDUの入力と最低frame数を検査してからreader設定を始める。入力拒否はsessionを保持する。設定失敗は`Cause::Preparation`として返し、applicationの送信progressとRF frame数を0に保ってsessionを失効させる。RF交換を開始した後の失敗もsessionを失効させ、attemptした入力prefix、確認済みprefix、受信済み応答、frame数をerrorに残す。送信chaining中に番号の異なるR-ACKを受けたときは直前のI-blockを再送できる。応答chaining中の重複I-blockには同じR-ACKを返す。readerがRF timeoutを報告した場合、送信中はR-NAKを送り、応答chainの受信中はR-ACKを再送する。USB取引の失敗はそのまま返す。単一I-blockのcommandは、RF timeout後に送ったR-NAKへの応答が異なる番号のR-ACKである場合に限り、同じI-blockを予算内で再送する。カードからのR-NAKはprotocol errorとして扱う。

カードhandleはreaderの排他的borrowを保持する。transport失敗後にはRF readinessが失効する。RF statusのmask後の値が0Dの場合も再初期化を要求する。0Bの場合はraw値を保持してエラーを返す前に10 msの待機を入れる。readerへの`initialize`は明示的な再同期であり、失敗したカード操作の再実行や結果照合ではない。`rf_off`の失敗はcallerが観測する。DropはOS resourceの解放だけを担当する。

MIFARE Classicはcallerが指定したkeyでreaderが認証し、成功したsector内のブロックに限り読取・書込みを許す。ブロック交換失敗でsector handleは失効する。

`ndef-read`と`ndef-write`は、`--type type1`で120-byte静的メモリのType 1、`--type a`でType 2／4A、`--type felica`でsystem 12FCのType 3、`--type b`でType 4Bを扱う。Type 2は必要に応じて物理セクターを切り替え、切替の第2パケットに対するRFタイムアウトをパッシブACKとして扱う。切替が不確定なら再初期化を要求する。Type 4はmapping 2.x／3.xの最初の公開読取可能なNDEF fileを扱う。通常・拡張ファイルの長さを区別し、mapping 3.xではオフセットオブジェクトで最大1 MiBのファイルを扱う。Type 1／2の書込みには初期化済みのNDEF TLVが必要で、置換後のTerminatorより後ろのTLVは参照されない。Type 3は属性ブロックのchecksumと更新中フラグを検査する。

`ndef-write --data HEX`はタグを開く前にNDEFのレコード境界と長さを検査する。空の`--data`はメッセージを消去する。`ndef-read`は格納されたbytesを返す。`ndef-decode HEX`はオフラインでレコードを復元し、type、ID、payloadを表示する。アプリケーション固有のpayloadは各レコードの利用側が解釈する。

書込みはメッセージを非公開にしてから本文を更新し、長さまたは属性ブロックを最後に確定する。失敗は永続書込み前の準備エラーと、更新開始・本文・公開の各段階を区別する。更新コマンド失敗時の確認済みbytes数は直前までの応答に基づく。再選択してタグの状態を確認してから、必要な回復操作を判断する。

選択済みFeliCaのRF待機には`A0`のhalf-ms fieldと`1C`のreader timerを設定する。reader timerはRF待機を秒単位へ切り上げてから`(ms-10)/10`をLE16で送り、成功した設定だけをRF modeに保持する。`raw-felica`は`4A`で選択を成立させてから`A0`で任意のpacketを交換する。送受信ともFeliCaの長さbyteを含み、アドレス・コマンド・暗号化の解釈は呼出側が行う。任意packetを許可した時点でtyped card handleのIDm authorityは消費される。

`systems`と`service-at`はカードが公開するsystem codeと選択system内のservice／areaを照会する。`write`は指定した単一の非暗号化サービスに16 bytes単位で送信する。13ブロック以下でも、block listとデータの合計がpacket長上限を超える要求は拒否する。カード固有の書込み制限はカードが判定する。`Error::FelicaRequest`は送信前の要求拒否、`Error::FelicaResponse`は送信後の応答異常を表す。送信後は書込み結果が不明な場合があり、自動再送や読戻しは行わない。認証・暗号化の処理を持つ呼出側は`FelicaCard::exchange_command`で選択済みIDm宛てにコマンドを交換できる。

取引のACKと応答は、それぞれの期限より前に完了した読み取りのbytesだけを受理する。同期I/Oの回収に必要な時間はbackendの契約に従う。

回復ではpipeの状態整理に加え、未完了commandを中断するhost ACKを送り、10 ms待って受信cacheを再整理する。ACKが直前のresetを確定する可能性もあるため、resetの最小待機時間を確保する。その後に許可するのはresetだけで、空本文のreset応答と確定ACKの完了・10 ms待機まで通常commandを許可しない。USB pipe resetだけをfirmware commandの中断として扱わない。中断前のカード操作の結果不明はcallerに残る。

### FeliCa の認証セッション

`felica-lite-s` feature は、system 88B4で選択したLite-Sカード（IC Type F1）に対する相互認証と、MAC_A付きのユーザーブロック読取・書込みを提供する。カード鍵と、認証ごとにCSPRNGで生成した新しい16-byte challengeは呼出側が供給する。認証は通常のカードhandleを消費し、以降の選択前にRFを切ってカードの認証状態を解消する。MAC不一致や交換失敗後は再選択と認証が必要。書込みはカードが報告した結果を返し、送信後に失敗した場合は書込み済みの可能性がある。Lite-SのMAC_Aは通信データを暗号化しない。

コアはLite-Sのプロトコル、MACの入力構成、session状態を所有する。2-key TDESは`des`、MACの比較は`subtle`、鍵用バッファの消去は`zeroize`に委譲する。TDES実装のメモリアクセスには鍵依存性があり、同一ホスト上のタイミング観測を排除する要件には別途対処が必要。

`felica-standard-aes` feature はFeliCa StandardのAES-128相互認証と、Read v2／Write v2による暗号化ブロックアクセスを提供する。選択したシステムに対応するノード鍵を認証順に渡し、個別化コードと認証ごとに新しいCSPRNG challengeを指定する。応答はMACと取引番号を検査してから公開する。送信後の失敗でセッションは失効し、書込み結果は再認証して確認する。AESとCMACはRustCryptoへ委譲し、暗号フレームと取引番号はコアが管理する。フレーム形式の参照は[FeliCa Card User's Manual (Unofficial Edition)](https://soltia48.github.io/felica-users-manual-unofficial/en/)のMutual Authentication and Secure Messaging Algorithms。

## NFC-DEP

`Reader::activate_dep`は指定された速度・通信モードでイニシエーターとして相手を選択する。`Reader::listen_passive_dep`は106／212／424 kbpsでパッシブターゲットとして待機する。ATRとDEPのRFフレーム処理はreader firmwareが担う。要求・応答は`MAX_DEP_MESSAGE_BYTES`以内で、継続フラグに基づいて分割・再結合する。NADは連結の先頭だけに付け、ターゲットは要求と同じアドレスで応答する。途中失敗ではコマンド投入済み・受理済みの長さと受信済みデータを返し、セッションを失効させる。ホストの待機時間は各フラグメントに適用する。LLCP等の上位protocolはcallerが処理する。

`dep-echo --data HEX`は6-byteの識別子suffixを指定して1要求を反射する。終了時の`finish`はresetと再初期化を行う。起動に失敗した場合は`initialize`で再同期する。

## Type 2 ターゲット

`Reader::listen_type2_ndef`は、08で始まる4-byte UIDと読み取り専用のNDEFを持つ106 kbpsのType 2ターゲットを起動する。`serve_next`はREADに応答し、HALTでセッションを終了する。他のコマンドには応答せず、データも変更しない。応答の結果が不明になった場合はセッションを失効させる。`finish`でreaderをRF-off状態に戻す。

## 検証境界

固定packet vectorはデバイスに送るフレームと応答の解釈を検証する。実機captureはUSBとRFの観測範囲を別途記録する。

実機検証では、`devices`による対象／service／path、`probe`のfirmware／model／設定checksum、`poll`のidentity／PMm、対象serviceを指定した`read`を別々に記録する。CLI出力はAPIの観測結果であり、USB bus上のZLPやRF timingのcaptureとは区別する。全firmware、PC/SC完全互換、全カードcommand／APDUの意味と副作用の成立は、この検証の対象に含めない。NFC-A／Bの固定vectorはカード実機の成功証拠ではない。

## 外部実装へ委譲する責務

UMDF と USB の ABI、WDF ライブラリのリンクは Microsoft の `windows-drivers-rs` に委譲する。ドライバは USB ターゲットの寿命、要求の所有権と転送期限を管理する。Windows クライアントと PC/SC 検証ツールの Windows ABI は `windows-sys` を使用する。

`serde_json`は固定fixtureの読取にだけ使うdev dependencyで、通常のlibrary／CLIへ入れない。JSON parserとそのformatter／string処理の依存、およびCargo targetに基づくbuild scriptはtest buildのtrust surfaceとして扱う。driverやPDFのsample codeを同梱・portする依存ではない。
