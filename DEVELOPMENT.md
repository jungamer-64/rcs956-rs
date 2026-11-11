# Development

`rcs956`はRC-S956のフレーム、取引状態、RF設定、カードプロトコルを所有する。`no_std`と`alloc`で動作し、crate全体で`unsafe_code`を禁止する。Rustからは`rcs956::reader::Reader`などを使用する。crateが定義する`Transport`へ同期転送、pipe回復、単調時計、待機を委譲し、期限・待機時間とエラー時の状態遷移はcrateで決める。OSのデバイス列挙、USB backend、ドライバとの通信は`Transport`の実装側が所有する。

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

## 設定とカードsession

初期化はreset／host ACK、設定bank読取、checksum／model検査、register設定、RF offを順に行う。失敗した初期化を成功状態として公開しない。設定imageの`E[FD..FE]`はUSB PIDとは別のmodel wordで、`Model::product`は既知のwordを製品へ対応付ける（`0211`はRC-S330/P、`0212`はRC-S330/S）。`E[03]`のbit 5は、`E[04]`（`72`〜`BA`）の位置に`E[BF]`より前で終わるUSB string descriptor形式の機器名があることを示す。機器名はRF設定に関与しないため、不正な機器名は`ConfigImage::device_name`のエラーとして返し、設定imageは失効させない。RF modeはprotocolと適用済みtimerを保持し、protocol変更時には対応する設定imageのtableを適用する。`4A`はFeliCaを212または424 kbps、NFC-A／Bを106 kbpsで1 target検出する。

NFC-AはUID（4／7／10 bytes）、SAK、optional ATSのTLとinterface byte境界を検査する。`TypeACard::into_raw`は型付き操作の権限を消費して、最大262 bytesの任意commandを許可する。raw交換はfragmentごとにreader statusを保持し、継続中は空の`40 target`による回収だけを許可する。継続中にhandleを手放した場合や回収が失敗した場合は再初期化が必要。完了したraw交換の後は、新たな選択前にRFを切り、Type 2のセクター選択などのカード状態を解消する。`TypeACard::exchange_apdu`はSAKとATSでISO-DEP activationを確認して継続応答をまとめ、交換に失敗した場合は部分応答を返す。

NFC-Aの`40`交換の要求待機は検出時の待機から始まり、`TypeACard::set_exchange_timeout`で以後の交換だけを変更できる。要求待機は整数msへ切り上げ、`32 02 0B 0B code`の段階値へ変換する。RF応答待機は最大3280 msへ制限され、`1C`にはその実効待機を使う。host待機は実効待機に1秒を加える。成功したselectorとreader timerだけを保持し、同値の設定送信を省略する。RF offやtargetの再選択でselectorは失効しないが、reset／不確定な設定失敗では失効する。`TypeAExchangeError::Preparation`はカードcommand送信前の設定失敗を示し、再初期化を要求する。`Exchange`はカード交換段階の失敗を示し、原因に応じてカードへの効果が不明になり得る。

NFC-BはATQB／ATTRIBを検査し、ISO-DEP targetには`TypeBSelection::IsoDep`でAPDU交換を、その他のprotocolには`TypeBSelection::Frame`で`40`による最大63 bytesのカードコマンド交換を提供する。`nfcb::PollOptions`の`profile`でreader設定imageのtable3（`Standard`）またはtable5（`Alternate`）を選び、`afi`でApplication Family Identifierを指定する。既定はtable3とAFI wildcard。FSCIは0〜8、FWIは0〜14、CIDは0〜14を受理し、非zero CIDはカードの対応を必要とする。`node_address`はATQBで対応を示したカードに限り、送受信chainの先頭I-blockにnode addressを付ける。ISO-DEPの送信frameはカードのFSCと64-byte reader容量の小さい方に制限する。受信はRC-S956のoptional activation extensionのFSDI（省略時5）と64-byte容量の小さい方を上限とする。MBLIが非zeroの場合は`FSC × 2^(MBLI − 1)`のカードbuffer上限も送信前に検査し、zeroの場合は上限不明として扱う。CRCはreaderに委譲する。FeliCaの非暗号化読取とNFC-Bの個別block交換は`A0`を使う。

NFC-BのAPDU交換前には`32 02 0B 0B 10`と`1C 80 8F 01`を設定する。`32/02`の実効待機3280 msから`1C`を決め、blockごとのFWI／WTX待機は`A0`へ独立に指定する。WTXで`1C`は変更しない。成功したselectorとtimerは別々に保持し、再検出やprotocol切替でtimerが変わればAPDU前に再適用する。設定の途中で失敗した場合はapplication blockを送信せず再初期化を要求する。

NFC-BのISO-DEP sessionはblock番号、送受信chaining、R-block、WTXを処理する。空のINFを持つ継続I-blockも受理し、応答bytesを増やさずblock番号とframe数を進めてR-ACKを返す。application入力は1〜65535 bytes、応答は65536 bytes、RF callbackは2048回、WTXは32回、protocol再送はblockごとに2回を上限とする。最低限の送信frame数だけでbudgetを超える入力は送信前に拒否する。初期block待機はATQBのFWIに基づく`330 us × 2^FWI`。WTXでは要求倍率を応答に返し、待機は倍率を掛けた値をFWI=14相当の上限に制限する。`poll_type_b`の`RfTimeout`は検出待機を指定し、NFC-Bの各block待機を上書きしない。`TypeBCard::check_presence`はAPDUの合間に現在のblock番号のR(NAK)を送る。ISO/IEC 14443-4では、カードは自身のblock番号と異なるR(NAK)に対し、直前のblockを再送せず、自身の番号を持つR(ACK)を返す。双方の番号は変わらない。RF timeoutでは同じR(NAK)をprotocol再送の上限まで繰り返す。確認できない結果はすべてsessionを失効させる。

APDUの入力と最低frame数を検査してからreader設定を始める。入力拒否はsessionを保持する。設定失敗は`Cause::Preparation`として返し、applicationの送信progressとRF frame数を0に保ってsessionを失効させる。RF交換を開始した後の失敗もsessionを失効させ、attemptした入力prefix、確認済みprefix、受信済み応答、frame数をerrorに残す。送信chaining中に番号の異なるR-ACKを受けたときは直前のI-blockを再送できる。応答chaining中の重複I-blockには同じR-ACKを返す。readerがRF timeoutを報告した場合、送信中はR-NAKを送り、応答chainの受信中はR-ACKを再送する。USB取引の失敗はそのまま返す。単一I-blockのcommandは、RF timeout後に送ったR-NAKへの応答が異なる番号のR-ACKである場合に限り、同じI-blockを予算内で再送する。カードからのR-NAKはprotocol errorとして扱う。

カードhandleはreaderの排他的borrowを保持する。transport失敗後にはRF readinessが失効する。RF statusのmask後の値が0Dの場合も再初期化を要求する。0Bの場合はraw値を保持してエラーを返す前に10 msの待機を入れる。readerへの`initialize`は明示的な再同期であり、失敗したカード操作の再実行や結果照合ではない。`rf_off`の失敗はcallerが観測する。DropはOS resourceの解放だけを担当する。

MIFARE Classicはcallerが指定したkeyでreaderが認証し、成功したsector内のブロックに限り読取・書込みを許す。ブロック交換失敗でsector handleは失効する。

`ndef`は`Type1Tag`で120-byte静的メモリのType 1、`TypeACard`でType 2／4A、`Type3Tag`でsystem 12FCのType 3、`TypeBCard`でType 4Bを扱う。Type 2は必要に応じて物理セクターを切り替え、切替の第2パケットに対するRFタイムアウトをパッシブACKとして扱う。切替が不確定なら再初期化を要求する。Type 4はmapping 2.x／3.xの最初の公開読取可能なNDEF fileを扱う。通常・拡張ファイルの長さを区別し、mapping 3.xではオフセットオブジェクトで最大1 MiBのファイルを扱う。Type 1／2の書込みには初期化済みのNDEF TLVが必要で、置換後のTerminatorより後ろのTLVは参照されない。Type 3は属性ブロックのchecksumと更新中フラグを検査する。

読取と書込みはタグに格納されたbytesをそのまま扱い、空のメッセージの書込みはメッセージを消去する。`ndef::Message::parse`はレコード境界と長さを検査してtype、ID、payloadを復元する。書込み前のレコード検査は呼出側が行う。アプリケーション固有のpayloadは各レコードの利用側が解釈する。

書込みはメッセージを非公開にしてから本文を更新し、長さまたは属性ブロックを最後に確定する。失敗は永続書込み前の準備エラーと、更新開始・本文・公開の各段階を区別する。更新コマンド失敗時の確認済みbytes数は直前までの応答に基づく。再選択してタグの状態を確認してから、必要な回復操作を判断する。

選択済みFeliCaのRF待機には`A0`のhalf-ms fieldと`1C`のreader timerを設定する。reader timerはRF待機を秒単位へ切り上げてから`(ms-10)/10`をLE16で送り、成功した設定だけをRF modeに保持する。`FelicaCard::into_raw`で得た`RawFelicaCard::exchange_packet`は、`4A`で成立した選択に`A0`で任意のpacketを交換する。送受信ともFeliCaの長さbyteを含み、アドレス・コマンド・暗号化の解釈は呼出側が行う。任意packetを許可した時点でtyped card handleのIDm authorityは消費される。

`FelicaCard::request_system_codes`と`FelicaCard::search_service_code`はカードが公開するsystem codeと選択system内のservice／areaを照会する。`FelicaCard::write_without_encryption`は指定した単一の非暗号化サービスに16 bytes単位で送信する。13ブロック以下でも、block listとデータの合計がpacket長上限を超える要求は拒否する。カード固有の書込み制限はカードが判定する。`Error::FelicaRequest`は送信前の要求拒否、`Error::FelicaResponse`は送信後の応答異常を表す。送信後は書込み結果が不明な場合があり、自動再送や読戻しは行わない。認証・暗号化の処理を持つ呼出側は`FelicaCard::exchange_command`で選択済みIDm宛てにコマンドを交換できる。

取引のACKと応答は、それぞれの期限より前に完了した読み取りのbytesだけを受理する。同期I/Oの回収に必要な時間はbackendの契約に従う。

回復ではpipeの状態整理に加え、未完了commandを中断するhost ACKを送り、10 ms待って受信cacheを再整理する。ACKが直前のresetを確定する可能性もあるため、resetの最小待機時間を確保する。その後に許可するのはresetだけで、空本文のreset応答と確定ACKの完了・10 ms待機まで通常commandを許可しない。USB pipe resetだけをfirmware commandの中断として扱わない。中断前のカード操作の結果不明はcallerに残る。

### FeliCa の認証セッション

`felica-lite-s` feature は、system 88B4で選択したLite-Sカード（IC Type F1）に対する相互認証と、MAC_A付きのユーザーブロック読取・書込みを提供する。カード鍵と、認証ごとにCSPRNGで生成した新しい16-byte challengeは呼出側が供給する。認証は通常のカードhandleを消費し、以降の選択前にRFを切ってカードの認証状態を解消する。MAC不一致や交換失敗後は再選択と認証が必要。書込みはカードが報告した結果を返し、送信後に失敗した場合は書込み済みの可能性がある。Lite-SのMAC_Aは通信データを暗号化しない。

コアはLite-Sのプロトコル、MACの入力構成、session状態を所有する。2-key TDESは`des`、MACの比較は`subtle`、鍵用バッファの消去は`zeroize`に委譲する。TDES実装のメモリアクセスには鍵依存性があり、同一ホスト上のタイミング観測を排除する要件には別途対処が必要。

`felica-standard-aes` feature はFeliCa StandardのAES-128相互認証と、Read v2／Write v2による暗号化ブロックアクセスを提供する。選択したシステムに対応するノード鍵を認証順に渡し、個別化コードと認証ごとに新しいCSPRNG challengeを指定する。応答はMACと取引番号を検査してから公開する。送信後の失敗でセッションは失効し、書込み結果は再認証して確認する。AESとCMACはRustCryptoへ委譲し、暗号フレームと取引番号はコアが管理する。フレーム形式の参照は[FeliCa Card User's Manual (Unofficial Edition)](https://soltia48.github.io/felica-users-manual-unofficial/en/)のMutual Authentication and Secure Messaging Algorithms。

## NFC-DEP

`Reader::activate_dep`は指定された速度・通信モードでイニシエーターとして相手を選択する。`Reader::listen_passive_dep`は106／212／424 kbpsでパッシブターゲットとして待機する。ATRとDEPのRFフレーム処理はreader firmwareが担う。要求・応答は`MAX_DEP_MESSAGE_BYTES`以内で、継続フラグに基づいて分割・再結合する。NADは連結の先頭だけに付け、ターゲットは要求と同じアドレスで応答する。途中失敗ではコマンド投入済み・受理済みの長さと受信済みデータを返し、セッションを失効させる。ホストの待機時間は各フラグメントに適用する。LLCP等の上位protocolはcallerが処理する。

終了時の`finish`はresetと再初期化を行う。起動に失敗した場合は`initialize`で再同期する。

## Type 2 ターゲット

`Reader::listen_type2_ndef`は、08で始まる4-byte UIDと読み取り専用のNDEFを持つ106 kbpsのType 2ターゲットを起動する。`serve_next`はREADに応答し、HALTでセッションを終了する。他のコマンドには応答せず、データも変更しない。応答の結果が不明になった場合はセッションを失効させる。`finish`でreaderをRF-off状態に戻す。

## 検証境界

固定packet vectorはデバイスに送るフレームと応答の解釈を検証する。実機captureはUSBとRFの観測範囲を別途記録する。

NFC-A／Bの固定vectorはカード実機の成功証拠ではない。全firmware、全カードcommand／APDUの意味と副作用の成立は、固定vectorの検証対象に含めない。

## 外部実装へ委譲する責務

`serde_json`は固定fixtureの読取にだけ使うdev dependencyで、通常のlibraryへ入れない。JSON parserとそのformatter／string処理の依存、およびCargo targetに基づくbuild scriptはtest buildのtrust surfaceとして扱う。
