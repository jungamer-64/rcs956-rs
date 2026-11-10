# Build and device validation

`rcs956-core`はフレーム、取引状態、RF設定、カードプロトコルを所有する。`no_std`と`alloc`で動作し、crate全体で`unsafe_code`を禁止する。Rustからは`rcs956_core::reader::Reader`などを使用する。coreが定義する`Transport`へ同期転送、pipe回復、単調時計、待機を委譲し、期限・待機時間とエラー時の状態遷移はcoreで決める。`rcs956`は`rcs956::windows::WinUsb`を提供し、`rcs956-cli`が両ライブラリを組み合わせて`rcs956`コマンドを提供する。

## Windowsでのビルドと検証

リポジトリのルートで実行する。coreの`no_std`検証にはベアメタル向けRust targetが必要。 rustdocの検証は、環境変数やターゲット別設定で`rustdocflags`を上書きしていない状態で行う。

```powershell
rustup target add x86_64-unknown-none
cargo build --workspace --locked
cargo fmt --all --check
cargo check --locked -p rcs956-core --lib --target x86_64-unknown-none
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo doc --locked --workspace --no-deps --config "build.rustdocflags=['-Dwarnings']"
```

## 実機での実行例

```powershell
cargo run --locked -p rcs956-cli -- devices
cargo run --locked -p rcs956-cli -- probe
cargo run --locked -p rcs956-cli -- poll --type felica --system FFFF --request 1 --slots 0
cargo run --locked -p rcs956-cli -- poll --type a
cargo run --locked -p rcs956-cli -- poll --type b
cargo run --locked -p rcs956-cli -- read --system 88B4 --service 000B --blocks 0,1
```

read例のservice／systemは対象カードに存在するものを指定する。未確認のカードへ例の値をそのまま適用しない。`--path`は複数リーダーの中から対象のapplication interfaceを指定する。同じUSB functionの複数aliasは1台として扱い、使用可能なfunctionが1台なら登録pathのソート順で先頭を選ぶ。`--timeout-ms`はRF交換の有限待機値で、host応答待機には余裕時間を加える。`exchange --type a --data HEX`はカードcommand、`exchange --type b --data HEX`はISO-DEP APDUを送る。送信内容とカードへの効果はcallerが決める。FeliCaのreadは非暗号化読取だけを行う。application commandの自動再実行はしない。

## Windows binding

ハードウェア操作には、対象USB functionがWinUSBで利用可能であることが必要。`WinUsb::open`はdescriptorと`054C:02E1`、Bulk IN／OUT、64-byte MPSを検査する。OSドライバーの自動インストール・置換、registryへの書込みは行わない。Sonyの既存private SDK interfaceはWinUSB interfaceとは別である。

WinUSBのapplication interface登録は、hardware key上の`DeviceInterfaceGUIDs`（REG_MULTI_SZ）と`DeviceInterfaceGUID`（REG_SZ）を読む。hardware keyは`SetupDiOpenDevRegKey(DIREG_DEV)`で開き、追加の`Device Parameters` subkeyは開かない。USB hubの存在通知interfaceをI/O候補に含めない。property／registry値の不在と、アクセス失敗・型不一致・不正な文字列を区別する。可変長metadataは64 KiBを上限に取得し、4回のqueryで確定しなければWouldBlockを返す。登録形式と取得APIの外部契約は[WinUSB installation](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation)と[hardware key](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/opening-a-device-s-hardware-key)を参照する。

WinUSBでないserviceが列挙された場合、`devices`の結果で実際のbindingを確認する。OSドライバーを変更する必要がある場合は、対象と復元方法を決めて別途実施する。`probe`成功はRF／カード読取成功を意味しない。

## 設定とカードsession

初期化はreset／host ACK、設定bank読取、checksum／model検査、register設定、RF offを順に行う。失敗した初期化を成功状態として公開しない。RF modeはprotocolと適用済みtimerを保持し、protocol変更時には対応する設定imageのtableを適用する。`4A`はFeliCaを212または424 kbps、NFC-A／Bを106 kbpsで1 target検出する。

NFC-AはUID（4／7／10 bytes）、SAK、optional ATSのTLとinterface byte境界を検査する。`TypeACard::into_raw`は型付き操作の権限を消費して、最大262 bytesの任意commandを許可する。raw交換はfragmentごとにreader statusを保持し、継続中は空の`40 target`による回収だけを許可する。`exchange --type a`は各fragmentを表示する。継続中にhandleを手放した場合や回収が失敗した場合は再初期化が必要。完了したraw交換の後は、新たな選択前にRFを切り、Type 2のセクター選択などのカード状態を解消する。`--type a-apdu`はSAKとATSでISO-DEP activationを確認して継続応答をまとめ、交換に失敗した場合は部分応答を返す。

NFC-Aの`40`交換では、要求待機を整数msへ切り上げ、`32 02 0B 0B code`の段階値へ変換する。RF応答待機は最大3280 msへ制限され、`1C`にはその実効待機を使う。host待機は実効待機に1秒を加える。成功したselectorとreader timerだけを保持し、同値の設定送信を省略する。RF offやtargetの再選択でselectorは失効しないが、reset／不確定な設定失敗では失効する。`TypeAExchangeError::Preparation`はカードcommand送信前の設定失敗を示し、再初期化を要求する。`Exchange`はカード交換段階の失敗を示し、原因に応じてカードへの効果が不明になり得る。

NFC-BはATQB／ATTRIBを検査し、ISO-DEP targetにAPDU交換を、その他のprotocolには`40`による最大63 bytesのカードコマンド交換を提供する。CLIではそれぞれ`--type b`と`--type b-frame`で選ぶ。`--b-profile`でreader設定imageのtable3（standard）またはtable5（alternate）を選び、`--afi`でApplication Family Identifierを指定する。既定はtable3とAFI wildcard。FSCIは0〜8、FWIは0〜14、CIDは0〜14を受理し、非zero CIDはカードの対応を必要とする。`--nad`はATQBで対応を示したカードに限り、送受信chainの先頭I-blockにnode addressを付ける。ISO-DEPの送信frameはカードのFSCと64-byte reader容量の小さい方に制限する。受信はRC-S956のoptional activation extensionのFSDI（省略時5）と64-byte容量の小さい方を上限とする。MBLIが非zeroの場合は`FSC × 2^(MBLI − 1)`のカードbuffer上限も送信前に検査し、zeroの場合は上限不明として扱う。CRCはreaderに委譲する。FeliCaの非暗号化読取とNFC-Bの個別block交換は`A0`を使う。

NFC-BのAPDU交換前には`32 02 0B 0B 10`と`1C 80 8F 01`を設定する。`32/02`の実効待機3280 msから`1C`を決め、blockごとのFWI／WTX待機は`A0`へ独立に指定する。WTXで`1C`は変更しない。成功したselectorとtimerは別々に保持し、再検出やprotocol切替でtimerが変わればAPDU前に再適用する。設定の途中で失敗した場合はapplication blockを送信せず再初期化を要求する。

NFC-BのISO-DEP sessionはblock番号、送受信chaining、R-block、WTXを処理する。空のINFを持つ継続I-blockも受理し、応答bytesを増やさずblock番号とframe数を進めてR-ACKを返す。application入力は1〜65535 bytes、応答は65536 bytes、RF callbackは2048回、WTXは32回、protocol再送は2回を上限とする。最低限の送信frame数だけでbudgetを超える入力は送信前に拒否する。初期block待機はATQBのFWIに基づく`330 us × 2^FWI`。WTXでは要求倍率を応答に返し、待機は倍率を掛けた値をFWI=14相当の上限に制限する。`--timeout-ms`は検出待機を指定し、NFC-Bの各block待機を上書きしない。

APDUの入力と最低frame数を検査してからreader設定を始める。入力拒否はsessionを保持する。設定失敗は`Cause::Preparation`として返し、applicationの送信progressとRF frame数を0に保ってsessionを失効させる。RF交換を開始した後の失敗もsessionを失効させ、attemptした入力prefix、確認済みprefix、受信済み応答、frame数をerrorに残す。送信chaining中に番号の異なるR-ACKを受けたときは直前のI-blockを再送できる。応答chaining中の重複I-blockには同じR-ACKを返す。readerがRF timeoutを報告した場合、送信中はR-NAKを送り、応答chainの受信中はR-ACKを再送する。USB取引の失敗はそのまま返す。単一I-blockのcommandは、RF timeout後に送ったR-NAKへの応答が異なる番号のR-ACKである場合に限り、同じI-blockを予算内で再送する。カードからのR-NAKはprotocol errorとして扱う。

カードhandleはreaderの排他的borrowを保持する。transport失敗後にはRF readinessが失効する。RF statusのmask後の値が0Dの場合も再初期化を要求する。0Bの場合はraw値を保持してエラーを返す前に10 msの待機を入れる。readerへの`initialize`は明示的な再同期であり、失敗したカード操作の再実行や結果照合ではない。`rf_off`の失敗はcallerが観測する。DropはOS resourceの解放だけを担当する。

MIFARE Classicはcallerが指定したkeyでreaderが認証し、成功したsector内のブロックに限り読取・書込みを許す。ブロック交換失敗でsector handleは失効する。`ndef-read`はNFC-AのType 2 tagまたはNFC-A／BのType 4 tagから公開読取可能なNDEF messageのbytesを取得する。Type 2の物理アドレスは先頭sectorに限り、Type 4はmapping 2.xのshort APDUで参照できるfileを扱う。

選択済みFeliCaのRF待機には`A0`のhalf-ms fieldと`1C`のreader timerを設定する。reader timerはRF待機を秒単位へ切り上げてから`(ms-10)/10`をLE16で送り、成功した設定だけをRF modeに保持する。`raw-felica`は`4A`で選択を成立させてから`A0`で任意のpacketを交換する。送受信ともFeliCaの長さbyteを含み、アドレス・コマンド・暗号化の解釈は呼出側が行う。任意packetを許可した時点でtyped card handleのIDm authorityは消費される。

`systems`と`service-at`はカードが公開するsystem codeと選択system内のservice／areaを照会する。`write`は指定した単一の非暗号化サービスに16 bytes単位で送信する。13ブロック以下でも、block listとデータの合計がpacket長上限を超える要求は拒否する。カード固有の書込み制限はカードが判定する。送信後のエラーでは書込み結果が不明な場合があり、自動再送や読戻しは行わない。認証・暗号化の処理を持つ呼出側は`FelicaCard::exchange_command`で選択済みIDm宛てにコマンドを交換できる。

取引のACKと応答は、それぞれの期限より前に完了した読み取りのbytesだけを受理する。同期I/Oの回収に必要な時間はbackendの契約に従う。

回復ではpipeの状態整理に加え、未完了commandを中断するhost ACKを送り、10 ms待って受信cacheを再整理する。ACKが直前のresetを確定する可能性もあるため、resetの最小待機時間を確保する。その後に許可するのはresetだけで、空本文のreset応答と確定ACKの完了・10 ms待機まで通常commandを許可しない。USB pipe resetだけをfirmware commandの中断として扱わない。中断前のカード操作の結果不明はcallerに残る。

## 検証境界

固定packet vectorは実機captureではない。registry取得のtestは隔離したvolatile HKCU keyを作成し、取得・型・アクセスエラーを実際のWindows APIで確認して終了時に削除する。deviceの登録やbindingには書き込まない。

実機検証では、`devices`による対象／service／path、`probe`のfirmware／model／設定checksum、`poll`のidentity／PMm、対象serviceを指定した`read`を別々に記録する。CLI出力はAPIの観測結果であり、USB bus上のZLPやRF timingのcaptureとは区別する。全firmware、PC/SC完全互換、全カードcommand／APDUの意味と副作用の成立は、この検証の対象に含めない。NFC-A／Bの固定vectorはカード実機の成功証拠ではない。

## 外部実装へ委譲する責務

Windows ABIの宣言とlinkはMicrosoftの`windows-sys`へ委譲し、`rcs956`がhandle lifetimeとFFI buffer境界を所有する。hostのruntimeの外部依存はそのABI projectionと`windows-link`。native codeの独自buildやFFI宣言の複製は行わない。

`serde_json`は固定fixtureの読取にだけ使うdev dependencyで、通常のlibrary／CLIへ入れない。JSON parserとそのformatter／string処理の依存、およびCargo targetに基づくbuild scriptはtest buildのtrust surfaceとして扱う。driverやPDFのsample codeを同梱・portする依存ではない。

WinUSBの同期I/OとZLP policyの外部契約は[MicrosoftのReadPipe定義](https://learn.microsoft.com/en-us/windows/win32/api/winusb/nf-winusb-winusb_readpipe)と[pipe policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-functions-for-pipe-policy-modification)を参照する。
