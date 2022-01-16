-module(erlang_apay_decrypt).

-define(LEAF_CERT_OID, {1, 2, 840, 113635, 100, 6, 29}).
-define(INTER_CERT_OID, {1, 2, 840, 113635, 100, 6, 2, 14}).
-define(OID_SIGNING_TIME, {1, 2, 840, 113549, 1, 9, 5}).

-export([
    verify_and_decrypt_apay_message/1,
    verify_and_decrypt_apay_message/2
]).

% Preparation

prepare_env(APayMessage) ->
    [].

% Main job

verify_and_decrypt_apay_message(APayMessage) ->
    verify_and_decrypt_apay_message(APayMessage, []).

verify_and_decrypt_apay_message(APayMessage, Opts) ->
    SkipChainCheck = 
        case proplists:get_value(skip_chain_check, Opts) of
            undefined -> false;
            false -> false;
            _X -> true
        end,

    Env = [
        {skip_chain_check, SkipChainCheck}
    ] ++ prepare_env(APayMessage),
    case verify_apay_message(APayMessage, Env) of
        ok -> decrypt_apay_message(APayMessage, Env);
        {error, _} = Err -> Err 
    end.

% Verification
verify_apay_message(APayMsg, Env) ->
    B64Signature = maps:get(<<"signature">>, APayMsg),
    Signature = base64:decode(B64Signature),
    Certs = extract_certs(Signature),
    case length(Certs) of
        2 -> 
            verify_apay_certs(Certs, Env);
        X -> {error, {unexpected_num_of_certs, X}}
    end.

extract_certs(Signature) ->
    {'ContentInfo', _Id, ContentInfo} = public_key:der_decode('ContentInfo', Signature),
    {certSet, CertSet} = element(5, ContentInfo),
    % {cert, Cert} -> Cert
    lists:map(fun (X) -> element(2, X) end, CertSet).

verify_apay_certs(Certs, Env) ->
    CertChain = extract_leaf_and_intermediate_certificates(Certs),
    case CertChain of
        {ok, CertChain1} -> 
            case verify_apay_cert_chain(CertChain1, Env) of
                {ok, _} -> ok;
                Err -> Err
            end;
        Err -> Err
    end.

extract_leaf_and_intermediate_certificates(Certs) ->
    ExtractedCerts = {
        find_cert_by_oid(Certs, ?LEAF_CERT_OID),
        find_cert_by_oid(Certs, ?INTER_CERT_OID)
    },
    case ExtractedCerts of
        {{error, _}, {error, _}} -> {error, no_required_certs};
        {{error, _}, _} -> {error, no_leaf_cert};
        {_, {error, _}} -> {error, no_intermediate_cert};
        {Leaf, Inter} -> {ok, [Inter, Leaf]}
    end.

find_cert_by_oid(Certs, OID) ->
    Searcher = fun(X) ->
        case get_extention_from_cert(X, OID) of
            {ok, _} -> true;
            _ -> false
        end
    end,

    case lists:search(Searcher, Certs) of
        false -> {error, no_such_cert};
        {value, V} -> V
    end.

verify_apay_cert_chain(CertChain, Env) ->
    case proplists:get_value(skip_chain_check) of
        false ->
            RootCert = proplists:get_value(root_cert, Env),
            RawCertChain = lists:map(fun (C) -> public_key:der_encode('Certificate', C) end, CertChain),
            public_key:pkix_path_validation(RootCert, RawCertChain, []);
        true -> ok
    end.

check_cms_signing_time(SigningTime, CheckTime, Threshold) ->
    ok.

check_signature_issuer(Signature, LeafCert) ->
    ok.

extract_singing_data(Signature) ->
    ok.

decrypt_apay_message(APayMsg, Env) ->
    EphKey = proplists:get_value(eph_key, Env),
    WKey = public_key:der_decode('SubjectPublicKeyInfo', EphKey),
    
    Key = element(3, WKey),
    PKey = proplists:get_value(private_key, Env),
    Curve = proplists:get_value(curve, Env),

    SharedSecret = crypto:compute_key(ecdh, Key, PKey, Curve),
    MerchHash = proplists:get_value(merch_hash, Env),
    
    SymKey = apay_kdf(SharedSecret, MerchHash),
    Data = proplists:get_value(data, Env),
    
    do_decrypt(Data, SymKey).

do_decrypt(Data, SymKey) -> 
    IV = <<0:128>>,
    DataSize = byte_size(Data) - 16,
    <<Data1:DataSize/binary, Tag/binary>> = Data,
    crypto:crypto_one_time_aead(aes_256_gcm, SymKey, IV, Data1, <<>>, Tag, false).

apay_kdf(SharedSecret, PartyV) ->
    KDFAlgo = <<13:1, "id-aes256-GCM">>,
    KDFInfo = <<KDFAlgo/binary, "Apple", PartyV/binary>>,
    Counter = <<1:32/big>>,
    ToHash = <<Counter/binary, SharedSecret/binary, KDFInfo/binary>>,
    crypto:hash(sha256, ToHash).

% Utils
normalize_oid(OID) ->
    OIDParts = binary:split(OID, <<".">>),
    OIDParts1 = lists:map(fun binary_to_integer/1, OIDParts),
    list_to_tuple(OIDParts1).

get_extention_from_cert(Cert, OID) when is_binary(OID) ->
    OID1 = normalize_oid(OID),
    get_extention_from_cert(Cert, OID1);

get_extention_from_cert(Cert, OID) when is_binary(OID) ->
    {_CertTag, Cert1, _Algo} = Cert,
    TBSCertificate = element(2, Cert1),
    Extentions = element(11, TBSCertificate),
    get_by_oid(Extentions, OID).

get_by_oid(Attrs, OID) ->
    Extention = lists:search(fun (X) -> element(2, X) == OID end, Attrs),
    case Extention of
        false -> {error, {no_extention, OID}};
        {value, V} -> {ok, V}
    end.