Verify static-policy coverage

MAKE SURE TO VERIFY AND RESET THE DATA COLLECTORS SO THEY DON'T HAVE RANDOM DATA FROM DEVELOPMENT RUNS

ADD A BISCUIT-THIRD-PARTY-SIGNING TEST.

MAKE THE RUMQTTC MQTT CLIENT CALL BISCUIT AUTH DIRECTLY (instead of through a sub process)

Remember to remove 'good-pulls' from all references in .git. completely wipe the file from the tree later.








Straight from OASIS: Binary token can't be passed on the username without encoding.

3.1.3.5 User Name
If the User Name Flag is set to 1, the User Name is the next field in the Payload. The User Name MUST be a UTF-8 Encoded String as defined in section 1.5.4 [MQTT-3.1.3-12]. It can be used by the Server for authentication and authorization. 


3.1.3.6 Password

If the Password Flag is set to 1, the Password is the next field in the Payload. The Password field is Binary Data. Although this field is called Password, it can be used to carry any credential information.


Mosquitto does not give us access to the CONNECT Auth Method or Auth Data in MQTTv5 with BASIC_AUTH: https://github.com/eclipse-mosquitto/mosquitto/issues/2269




Current python client uses a subprocess calling a binary to attenuate the token

It should call with the python-buscit library to be faster.
If we port to Go, go-biscuit does not have support for post 3.0 features (such as third party blocks)

```md
def _attenuate_biscuit_token(token: str, cfg: WorkerConfig) -> tuple[str, float, int]:
    cmd = _build_biscuit_attenuate_cmd(
        token,
        custom_bin=cfg.biscuit_attenuate_bin,
        public_key_hex=cfg.biscuit_public_key_hex,
        public_key_file=cfg.biscuit_public_key_file,
        restrict_topic=cfg.biscuit_attenuate_topic,
        restrict_operation=cfg.biscuit_attenuate_operation,
        ttl_seconds=cfg.biscuit_attenuate_ttl,
        denies=cfg.biscuit_attenuate_denies,
        checks=cfg.biscuit_attenuate_checks,
    )
    t0 = time.perf_counter()
    output = subprocess.check_output(cmd, ...).decode("utf-8")
    t1 = time.perf_counter()
    token_out = output.strip()
    return token_out, (t1 - t0) * 1000.0, len(token_out)
```
