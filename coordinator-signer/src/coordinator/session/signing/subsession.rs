pub(crate) struct SubSession<VI: ValidatorIdentity> {
    pub(crate) crypto_type: CryptoType,
    pub(crate) subsession_id: SubSessionId<VI::Identity>,
    pub(crate) min_signers: u16,
    pub(crate) participants: BTreeMap<u16, VI::Identity>,
    pub(crate) state: SigningState<VI::Identity>,
    pub(crate) pk: PublicKeyPackage,
    pub(crate) pkid: PKID,
    pub(crate) signing_sender: UnboundedSender<(
        SigningSingleRequest<VI::Identity>,
        oneshot::Sender<SigningSingleResponse<VI::Identity>>,
    )>,
    pub(crate) signature_sender: UnboundedSender<SignatureSuite<VI>>,
}
impl<VI: ValidatorIdentity> SubSession<VI> {
    pub(crate) fn new(
        session_id: SessionId<VI::Identity>,
        pkid: PKID,
        pk: PublicKeyPackage,
        min_signers: u16,
        participants: BTreeMap<u16, VI::Identity>,
        crypto_type: CryptoType,
        sign_message: Vec<u8>,
        sender: UnboundedSender<(
            SigningSingleRequest<VI::Identity>,
            oneshot::Sender<SigningSingleResponse<VI::Identity>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI>>,
    ) -> Result<Self, SessionError> {
        let subsession_id = SubSessionId::new(
            crypto_type,
            min_signers,
            &participants,
            sign_message.clone(),
            &session_id,
            pkid.clone(),
        )?;
        Ok(Self {
            subsession_id: subsession_id.clone(),
            min_signers,
            participants: participants.clone(),
            crypto_type,
            pkid: pkid.clone(),
            pk: pk.clone(),
            signature_sender,
            state: SigningState::Round1 {
                crypto_type,
                message: sign_message,
                min_signers,
                pkid: pkid,
                subsession_id,
                pk: pk,
                participants,
            },
            signing_sender: sender,
        })
    }
    pub(crate) async fn start_signing<T: AsRef<[u8]>>(mut self, msg: T) {
        tracing::debug!("Starting Signing session with id: {:?}", self.subsession_id);
        let msg_v = msg.as_ref().to_vec();
        tokio::spawn(async move {
            let signature = loop {
                if let Some(signature) = self.state.completed() {
                    break signature;
                }
                tracing::info!("Starting new Signing round");
                let mut futures = FuturesUnordered::new();
                for request in self.state.split_into_single_requests() {
                    tracing::debug!("Sending DKG request: {:?}", request);
                    let (tx, rx) = oneshot::channel();
                    futures.push(rx);
                    if let Err(e) = self.signing_sender.send((request.clone(), tx)) {
                        tracing::error!("Error sending DKG state: {}", e);
                        tracing::debug!("Failed request was: {:?}", request);
                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            Settings::global().session.state_channel_retry_interval,
                        ))
                        .await;
                    }
                }
                let mut responses = BTreeMap::new();
                tracing::info!("Waiting for {} responses", self.participants.len());
                for i in 0..self.participants.len() {
                    tracing::debug!("Waiting for response {}/{}", i + 1, self.participants.len());
                    let response = futures.next().await;
                    match response {
                        Some(Ok(response)) => {
                            tracing::debug!("Received valid response: {:?}", response);
                            responses.insert(response.get_identity(), response);
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving DKG state: {}", e);
                            tracing::debug!("Breaking out of response collection loop");
                            break;
                        }
                        None => {
                            tracing::error!("DKG state is not completed");
                            tracing::debug!(
                                "Received None response, breaking out of collection loop"
                            );
                            break;
                        }
                    }
                }
                if responses.len() == self.participants.len() {
                    tracing::debug!("Received all {} responses, handling them", responses.len());
                    let result = self.state.handle_response(responses);
                    match result {
                        Ok(next_state) => {
                            tracing::debug!("Successfully transitioned to next DKG state");
                            self.state = next_state;
                        }
                        Err(e) => {
                            tracing::error!("Error handling DKG state: {}", e);
                            tracing::debug!("Retrying after interval");
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                Settings::global().session.state_channel_retry_interval,
                            ))
                            .await;
                            continue;
                        }
                    }
                } else {
                    tracing::error!(
                        "DKG state is not completed, got {}/{} responses",
                        responses.len(),
                        self.participants.len()
                    );
                    tracing::debug!("Retrying after interval");
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        Settings::global().session.state_channel_retry_interval,
                    ))
                    .await;
                    continue;
                }
            };
            if let Err(e) = self.signature_sender.send(SignatureSuite {
                signature,
                pk: self.pk.clone(),
                subsession_id: self.subsession_id.clone(),
                pkid: self.pkid.clone(),
                message: msg_v,
            }) {
                tracing::error!("Error sending signing session: {:?}", e);
            }
        });
    }

    pub(crate) fn get_subsession_id(&self) -> SubSessionId<VI::Identity> {
        self.subsession_id.clone()
    }
}
