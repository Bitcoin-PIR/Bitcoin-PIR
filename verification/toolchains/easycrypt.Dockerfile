# This verifier is owned by the product repository, not by the proof source
# repository. Its digest is checked by verification/locks/formal-proofs.json.
FROM ghcr.io/easycrypt/ec-build-box@sha256:5a46a4d816e763ad5de9ee9502d52158c742b9b98cc1f60c443d135a270fdb6a

ARG EASYCRYPT_COMMIT=dd9bd930d45e81980e546fc835ed2022418644be
ARG OCAML_VERSION=4.14.1
ARG WHY3_VERSION=1.8.2
ARG ALT_ERGO_VERSION=2.6.3
ARG PROOF_SWITCH=bitcoinpir-proof

ENV OPAMJOBS=1 \
    DUNEJOBS=1

RUN opam switch create --no-switch "${PROOF_SWITCH}" \
      "ocaml-base-compiler.${OCAML_VERSION}"

RUN opam pin add --switch="${PROOF_SWITCH}" -n why3 "${WHY3_VERSION}" && \
    opam pin add --switch="${PROOF_SWITCH}" -n alt-ergo "${ALT_ERGO_VERSION}" && \
    opam pin add --switch="${PROOF_SWITCH}" -n easycrypt \
      "git+https://github.com/EasyCrypt/easycrypt.git#${EASYCRYPT_COMMIT}"

RUN opam install --switch="${PROOF_SWITCH}" --jobs=1 \
      --confirm-level=unsafe-yes alt-ergo easycrypt

RUN rm -f "$HOME/.why3.conf" "$HOME/.config/easycrypt/why3.conf" && \
    opam exec --switch="${PROOF_SWITCH}" -- easycrypt why3config

WORKDIR /proofs
ENTRYPOINT ["opam", "exec", "--switch=bitcoinpir-proof", "--"]
