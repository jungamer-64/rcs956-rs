# Build and device validation

`Cargo.toml`がcrate構成、`Cargo.lock`が解決済み依存、`verify.ps1`がWindows上の正規検証手順を所有する。

```powershell
cargo build --locked
.\verify.ps1
cargo run --locked -- devices
cargo run --locked -- probe
cargo run --locked -- poll --system FFFF --request 1 --slots 0
cargo run --locked -- read --system 88B4 --service 000B --blocks 0,1
```

read例のservice／systemは対象カードに存在するものを指定する。未確認のカードへ例の値をそのまま適用しない。`--path`は複数リーダーの中から対象のapplication interfaceを指定する。同じUSB functionの複数aliasは1台として扱い、使用可能なfunctionが1台なら登録pathのソート順で先頭を選ぶ。`--timeout-ms`はRF交換の有限待機値で、host応答待機には余裕時間を加える。書込みCLIと自動再送は提供しない。

## Windows binding

ハードウェア操作には、対象USB functionがWinUSBで利用可能であることが必要。CLIはdescriptorと`054C:02E1`、Bulk IN／OUT、64-byte MPSを検査する。OSドライバーの自動インストール・置換、registryへの書込みは行わない。Sonyの既存private SDK interfaceはWinUSB interfaceとは別である。

WinUSBのapplication interface登録は、hardware key上の`DeviceInterfaceGUIDs`（REG_MULTI_SZ）と`DeviceInterfaceGUID`（REG_SZ）を読む。hardware keyは`SetupDiOpenDevRegKey(DIREG_DEV)`で開き、追加の`Device Parameters` subkeyは開かない。USB hubの存在通知interfaceをI/O候補に含めない。property／registry値の不在と、アクセス失敗・型不一致・不正な文字列を区別する。可変長metadataは64 KiBを上限に取得し、4回のqueryで確定しなければWouldBlockを返す。登録形式と取得APIの外部契約は[WinUSB installation](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation)と[hardware key](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/opening-a-device-s-hardware-key)を参照する。

WinUSBでないserviceが列挙された場合、`devices`の結果で実際のbindingを確認する。OSドライバーを変更する必要がある場合は、対象と復元方法を決めて別途実施する。`probe`成功はRF／カード読取成功を意味しない。

## 設定とカードsession

初期化はreset／host ACK、設定bank読取、checksum／model検査、register設定、RF offを順に行う。失敗した初期化を成功状態として公開しない。FeliCa検出時には通常212 kbps用tableを設定し、`4A`の応答からカード情報を取り出す。読取は`A0`によるカードpacket交換を使う。

カードhandleはreaderの排他的borrowを保持する。transport失敗後にはRF readinessが失効する。RF statusのmask後の値が0Dの場合も再初期化を要求する。0Bの場合はraw値を保持してエラーを返す前に10 msの待機を入れる。readerへの`initialize`は明示的な再同期であり、失敗したカード操作の再実行や結果照合ではない。`rf_off`の失敗はcallerが観測する。DropはOS resourceの解放だけを担当する。

RF待機には`A0`のhalf-ms fieldと`1C`のreader timerを両方設定する。reader timerはRF待機を秒単位へ切り上げてから`(ms-10)/10`をLE16で送り、成功した設定だけをRF modeに保持する。同じ設定の再送は省略し、待機時間を変えた場合はカード交換より先に更新する。

回復ではpipeの状態整理に加え、未完了commandを中断するhost ACKを送り、10 ms待って受信cacheを再整理する。ACKが直前のresetを確定する可能性もあるため、resetの最小待機時間を確保する。その後に許可するのはresetだけで、reset応答と確定ACKの完了・10 ms待機まで通常commandを許可しない。USB pipe resetだけをfirmware commandの中断として扱わない。中断前のカード操作の結果不明はcallerに残る。

## 検証境界

`verify.ps1`はcodec、command順序／失敗時progress、設定imageとcard packetの検査、および公開APIを確認する。固定packet vectorは実機captureではない。 registry取得のtestは隔離したvolatile HKCU keyを作成し、取得・型・アクセスエラーを実際のWindows APIで確認して終了時に削除する。deviceの登録やbindingには書き込まない。

実機検証では、`devices`による対象／service／path、`probe`のfirmware／model／設定checksum、`poll`のidentity／PMm、対象serviceを指定した`read`を別々に記録する。CLI出力はAPIの観測結果であり、USB bus上のZLPやRF timingのcaptureとは区別する。全firmware、PC/SC完全互換、Type A／B、カードへの書込みの成立はこの検証の対象に含めない。

## 外部実装へ委譲する責務

Windows ABIの宣言とlinkはMicrosoftの`windows-sys`へ委譲し、handle lifetime・buffer境界・protocol状態はこのcrateが所有する。runtimeの外部依存はそのABI projectionと`windows-link`。native codeの独自buildやFFI宣言の複製は行わない。

`serde_json`は固定fixtureの読取にだけ使うdev dependencyで、通常のlibrary／CLIへ入れない。JSON parserとそのformatter／string処理の依存、およびCargo targetに基づくbuild scriptはtest buildのtrust surfaceとして扱う。driverやPDFのsample codeを同梱・portする依存ではない。

WinUSBの同期I/OとZLP policyの外部契約は[MicrosoftのReadPipe定義](https://learn.microsoft.com/en-us/windows/win32/api/winusb/nf-winusb-winusb_readpipe)と[pipe policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-functions-for-pipe-policy-modification)を参照する。
