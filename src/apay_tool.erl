-module(apay_tool).

-export([
  config/1,
  parse/2,
  verify/2,
  decrypt/2
]).

-include_lib("public_key/include/public_key.hrl").

-define(OID_LEAF_MARKER, {1,2,840,113635,100,6,29}).
-define(OID_INTERMEDIATE_MARKER, {1,2,840,113635,100,6,2,14}).
-define(OID_SIGNING_TIME, ?'pkcs-9-at-signingTime'). %{1,2,840,113549,1,9,5}
-define(OID_MESSAGE_DIGEST, ?'pkcs-9-at-messageDigest'). %{1,2,840,113549,1,9,4}


config(Opts) ->
  is_map(Opts)
    orelse erlang:error({badarg, Opts}),
  case {maps:get(skip_chain_verification, Opts, false), maps:get(certificate_root, Opts, undefined)} of
    {true, undefined} -> ok;
    {_, Cert} when is_binary(Cert) -> ok;
    _ -> erlang:error({misconfigured, certificate_root})
  end,
  case maps:get(merchant_id, Opts, undefined) of
    {sha, _} -> ok;
    {raw, _} -> ok;
    Fm when is_function(Fm, 1) -> ok;
    _ -> erlang:error({misconfigured, merchant_id})
  end,
  case maps:get(private_key, Opts, undefined) of
    Raw when is_binary(Raw) -> ok;
    Fk when is_function(Fk, 1) -> ok;
    _ -> erlang:error({misconfigured, private_key})
  end,
  Defaults = #{
    verify_signing_time => false
  },
  maps:merge(Defaults, Opts).

get_private_key(Id, #{private_key := PKorLoader}) ->
  PemEntries = case PKorLoader of
    RawData when is_binary(RawData) ->
      public_key:pem_decode(RawData);
    Loader when is_function(Loader, 1) ->
      public_key:pem_decode(Loader(Id))
  end,
  Found = [E ||
    {Type, _, _} = E <- PemEntries,
    lists:member(Type, ['ECPrivateKey', 'RSAPrivateKey'])
  ],
  public_key:pem_entry_decode(hd(Found)).

get_merchant_id_hash(Id, #{merchant_id := MerchantId}) ->
  Data = case MerchantId of
    {_, _} = D -> D;
    F when is_function(F, 1) -> F(Id)
  end,
  case Data of
    {raw, Text} -> crypto:hash(sha256, Text);
    {sha, SHA} -> SHA
  end.


parse(Token, _Config) ->
  Vsn = case maps:get(<<"version">>, Token, undefined) of
    <<"RSA_v1">> -> rsa_v1;
    <<"EC_v1">> -> ec_v1;
    undefined -> erlang:error({invalid_token, missing_version});
    UV -> erlang:error({invalid_token, {unknown_version, UV}})
  end,
  Signature = try
    B64Sig = maps:get(<<"signature">>, Token),
    SigDER = base64:decode(B64Sig),
    #'ContentInfo'{
      content = SignedData
    } = public_key:der_decode('ContentInfo', SigDER),
    SignedData
  catch
    _:{badkey, _} -> erlang:error({invalid_token, missing_signature});
    _:_ -> erlang:error({invalid_token, malformed_signature})
  end,
  Data = try base64:decode(maps:get(<<"data">>, Token)) catch
    _:{badkey, _} -> erlang:error({invalid_token, missing_data});
    _:_ -> erlang:error({invalid_token, malformed_data})
  end,
  TokenHdr = maps:get(<<"header">>, Token, #{}),
  TxId = try base16_decode(maps:get(<<"transactionId">>, TokenHdr)) catch
    _:{badkey, _} -> erlang:error({invalid_token, missing_transaction_id});
    _:_ -> erlang:error({invalid_token, malformed_transaction_id})
  end,
  MerchanKeyHash = try base64:decode(maps:get(<<"publicKeyHash">>, TokenHdr)) catch
    _:{badkey, _} -> erlang:error({invalid_token, missing_pubkey_hash});
    _:_ -> erlang:error({invalid_token, malformed_pubkey_hash})
  end,
  AppData = try base16_decode(maps:get(<<"applicationData">>, TokenHdr, <<>>)) catch
    _:_ -> erlang:error({invalid_token, malformed_application_data})
  end,
  TokenKey = case Vsn of
    rsa_v1 -> try base64:decode(maps:get(<<"wrappedKey">>, TokenHdr)) catch
      _:{badkey, _} -> erlang:error({invalid_token, missing_wrapped_key});
      _:_ -> erlang:error({invalid_token, malformed_wrapped_key})
    end;
    ec_v1 -> try base64:decode(maps:get(<<"ephemeralPublicKey">>, TokenHdr)) catch
      _:{badkey, _} -> erlang:error({invalid_token, missing_ephemeral_key});
      _:_ -> erlang:error({invalid_token, malformed_ephemeral_key})
    end
  end,
  #{
    version => Vsn,
    signature => Signature,
    data => Data,
    key => TokenKey,
    tx_id => TxId,
    application_data => AppData,
    merchant_key_hash => MerchanKeyHash
  }.

message_for_signing(ParsedToken) ->
  #{
    data := Data,
    key := Key,
    tx_id := TxId,
    application_data := AppData
  } = ParsedToken,
  [Key, Data, TxId, AppData].


verify(#{signature := SI0} = ParsedToken, Config) ->
  Message = message_for_signing(ParsedToken),
  #'SignedData'{
    certificates = {certSet, CS},
    signerInfos = {siSet, SIs}
  } = SI = patch(SI0),
  pkcs7_verify(Message, SI, Config),

  {Leaf, Intermediate} = find_apay_certificates([C || {certificate, C} <- CS]),
  verify_apple_certificates(Leaf, Intermediate, Config),
  LeafTBS = Leaf#'OTPCertificate'.tbsCertificate,
  LeafSerial = LeafTBS#'OTPTBSCertificate'.serialNumber,

  Found = [S || #'SignerInfo'{
    issuerAndSerialNumber = #'IssuerAndSerialNumber'{serialNumber = SN}
  } = S <- SIs, SN == LeafSerial],
  length(Found) == 1
    orelse erlang:error({bad_signature, not_signed_by_leaf}).

patch(#'SignedData'{version = sdVer1, certificates = {certSet, CS}} = SD) ->
  % replace #'Certificate' with #'OTPCertificate'
  CS1 = lists:map(fun ({certificate, C}) ->
    C1 = public_key:pkix_decode_cert(
      public_key:der_encode('Certificate', C), otp),
    {certificate, C1}
  end, CS),
  SD#'SignedData'{
    certificates = {certSet, CS1}
  }.

find_apay_certificates(Certs) ->
  Leaf = case lists:search(extension_oid_predicate(?OID_LEAF_MARKER), Certs) of
    {value, L} -> L;
    false -> erlang:error({bad_signature, {certificate_missing, {leaf, ?OID_LEAF_MARKER}}})
  end,
  Intermediate = case lists:search(extension_oid_predicate(?OID_INTERMEDIATE_MARKER), Certs) of
    {value, I} -> I;
    false -> erlang:error({bad_signature, {certificate_missing, {intermediate, ?OID_INTERMEDIATE_MARKER}}})
  end,
  {Leaf, Intermediate}.

extension_oid_predicate(OID) ->
  fun (Cert) ->
    #'OTPCertificate'{
      tbsCertificate = #'OTPTBSCertificate'{
        extensions = Exts
      }
    } = Cert,
    lists:keyfind(OID, #'Extension'.extnID, Exts) =/= false
  end.

verify_apple_certificates(_, _, #{skip_chain_verification := true}) -> ok;
verify_apple_certificates(Leaf, Intermediate, #{certificate_root := Root}) ->
  case public_key:pkix_path_validation(Root, [Intermediate, Leaf], []) of
    {error, Reason} -> erlang:error({bad_signature, Reason});
    _ -> ok
  end.


pkcs7_verify(Message, #'SignedData'{version = Vsn} = SD, Config) ->
  Vsn == sdVer1 orelse erlang:error({unsupported_version, Vsn}),
  #'SignedData'{
    certificates = {certSet, CS},
    signerInfos = {siSet, SignerInfos}
  } = SD,
  CertList = [C || {certificate, C} <- CS],
  lists:foreach(fun(SI) ->
    verify_signer_info(Message, SI, CertList, Config)
  end, SignerInfos).

verify_signer_info(Message, #'SignerInfo'{version = siVer1} = SI, CertList, Config) ->
  #'SignerInfo'{
    issuerAndSerialNumber = #'IssuerAndSerialNumber'{serialNumber = Serial},
    digestAlgorithm = {_, HashType, _},
    digestEncryptionAlgorithm = {_, _SignType, _},
    authenticatedAttributes = AuthenticatedAttributes,
    encryptedDigest = Digest
  } = SI,
  AuthenticatedAttributes == undefined
    andalso erlang:error({unsupported, authenticated_attributes_missing}),
  {aaSet, AAs} = AuthenticatedAttributes,

  Found = [PKI ||
    #'OTPCertificate'{
      tbsCertificate = #'OTPTBSCertificate'{
        serialNumber = S,
        subjectPublicKeyInfo = PKI
      }
    } <- CertList, S == Serial],
  length(Found) > 0 orelse erlang:error({no_certificate_found, {serial, Serial}}),

  #'OTPSubjectPublicKeyInfo'{
    algorithm = {_, _, NamedCurve},
    subjectPublicKey = ECPoint
  } = hd(Found),
  PublicKey = {ECPoint, NamedCurve},

  SigningTime = case lists:keyfind(?OID_SIGNING_TIME, #'AttributePKCS-7'.type, AAs) of
    #'AttributePKCS-7'{values = [TimeStr]} -> pubkey_cert:time_str_2_gregorian_sec(TimeStr);
    false -> undefined
  end,
  verify_signing_time(SigningTime, Config),

  MessageDigest = crypto:hash(public_key:pkix_hash_type(HashType), Message),
  AttributeDigest = case lists:keyfind(?OID_MESSAGE_DIGEST, #'AttributePKCS-7'.type, AAs) of
    #'AttributePKCS-7'{values = V} -> hd(V);
    false -> erlang:error({bad_signature, no_digest_attribute})
  end,
  AttributeDigest == MessageDigest
    orelse erlang:error({bad_signature, {digest_mismatch, message}}),

  AASetDER = case public_key:der_encode('SignerInfoAuthenticatedAttributes', AuthenticatedAttributes) of
    % TODO: describe this clusterfuck
    <<160:8, Rest/binary>> -> <<49:8, Rest/binary>>;
    Other -> Other
  end,

  public_key:verify(AASetDER, public_key:pkix_hash_type(HashType), Digest, PublicKey)
    orelse erlang:error({bad_signature, {digest_mismatch, attributes}});

verify_signer_info(_, #'SignerInfo'{version = Vsn}, _, _) ->
  erlang:error({unsupported_version, Vsn}).

verify_signing_time(_, #{verify_signing_time := false}) -> ok;
verify_signing_time(Time, #{verify_signing_time := Fn}) when is_function(Fn) ->
  Fn(Time) orelse erlang:error({bad_signature, bad_signing_time}).


decrypt(ParsedToken, Config) ->
  #{
    version := Vsn,
    data := Data,
    merchant_key_hash := PubKeyId
  } = ParsedToken,
  PrivateKey = get_private_key(PubKeyId, Config),
  SymmetricKey = symmetric_key(ParsedToken, PrivateKey, Config),
  do_decrypt(Vsn, Data, SymmetricKey).

do_decrypt(Vsn, Data, Key) ->
  IV = <<0:128>>,
  DataSize = byte_size(Data) - 16,
  <<Data1:DataSize/binary, Tag/binary>> = Data,
  Algo = case Vsn of
    ec_v1 -> aes_256_gcm;
    rsa_v1 -> aes_128_gcm
  end,
  crypto:crypto_one_time_aead(Algo, Key, IV, Data1, <<>>, Tag, false).

symmetric_key(#{version := ec_v1} = ParsedToken, MerchantPrivateKey, Config) ->
  #{
    key := EphemeralKey,
    merchant_key_hash := KeyHash
  } = ParsedToken,
  #'SubjectPublicKeyInfo'{
    subjectPublicKey = PubKey
  } = try public_key:der_decode('SubjectPublicKeyInfo', EphemeralKey) catch
    _ -> erlang:error({invalid_token, malformed_ephemeral_key})
  end,
  #'ECPrivateKey'{
    privateKey = PrivateKey,
    parameters = {namedCurve, Curve}
  } = MerchantPrivateKey,
  SharedSecret = crypto:compute_key(ecdh, PubKey, PrivateKey, pubkey_cert_records:namedCurves(Curve)),
  MerchHash = get_merchant_id_hash(KeyHash, Config),
  apay_kdf(SharedSecret, MerchHash).

apay_kdf(SharedSecret, PartyV) ->
  KDFAlgo = <<16#0D:8, "id-aes256-GCM">>,
  Counter = <<1:32/big>>,
  ToHash = <<
    Counter/binary,
    SharedSecret/binary,
    KDFAlgo/binary,
    "Apple",
    PartyV/binary
  >>,
  crypto:hash(sha256, ToHash).


base16_decode(Hex) when is_binary(Hex), byte_size(Hex) rem 2 =:= 0 ->
    << <<((hex_to_halfbyte(H) bsl 4) bor (hex_to_halfbyte(L) band 15))>> || <<H:8, L:8>> <= Hex >>;
base16_decode(Hex) when is_binary(Hex), byte_size(Hex) rem 2 =:= 1 ->
    base16_decode(<<"0", Hex/binary>>).

hex_to_halfbyte(Hex) when Hex >= $0, Hex =< $9 -> Hex - $0;
hex_to_halfbyte(Hex) when Hex >= $A, Hex =< $F -> Hex - $A + 10;
hex_to_halfbyte(Hex) when Hex >= $a, Hex =< $f -> Hex - $a + 10.
