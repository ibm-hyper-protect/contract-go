package types

import ENV "github.com/ibm-hyper-protect/contract-go/environment"

func (logdna *LogDNA) GetIngestionKey() string {
	return logdna.IngestionKey
}

func (logdna *LogDNA) GetHostname() string {
	return logdna.Hostname
}

func (logdna *LogDNA) GetPort() *int {
	return logdna.Port
}

func (logdna *LogDNA) GetTags() []string {
	return logdna.Tags
}

func (logdna *LogDNA) SetIngestionKey(IngestionKey string) *LogDNA {
	logdna.IngestionKey = IngestionKey
	return logdna
}

func (logdna *LogDNA) SetHostname(Hostname string) *LogDNA {
	logdna.Hostname = Hostname
	return logdna
}

func (logdna *LogDNA) SetPort(Port *int) *LogDNA {
	logdna.Port = Port
	return logdna
}

func (logdna *LogDNA) SetTags(Tags []string) *LogDNA {
	logdna.Tags = Tags
	return logdna
}
func (syslog *SysLog) GetServer() string {
	return syslog.Server
}

func (syslog *SysLog) GetHostname() string {
	return syslog.Hostname
}

func (syslog *SysLog) GetPort() *int {
	return syslog.Port
}

func (syslog *SysLog) GetCert() *string {
	return syslog.Cert
}

func (syslog *SysLog) GetKey() *string {
	return syslog.Key
}

func (syslog *SysLog) SetServer(Server string) *SysLog {
	syslog.Server = Server
	return syslog
}

func (syslog *SysLog) SetHostname(Hostname string) *SysLog {
	syslog.Hostname = Hostname
	return syslog
}

func (syslog *SysLog) SetPort(Port *int) *SysLog {
	syslog.Port = Port
	return syslog
}

func (syslog *SysLog) SetCert(Cert *string) *SysLog {
	syslog.Cert = Cert
	return syslog
}

func (syslog *SysLog) SetKey(Key *string) *SysLog {
	syslog.Key = Key
	return syslog
}
func (logging *Logging) GetLogDNA() *LogDNA {
	return logging.LogDNA
}

func (logging *Logging) GetSysLog() *SysLog {
	return logging.SysLog
}

func (logging *Logging) SetLogDNA(LogDNA *LogDNA) *Logging {
	logging.LogDNA = LogDNA
	return logging
}

func (logging *Logging) SetSysLog(SysLog *SysLog) *Logging {
	logging.SysLog = SysLog
	return logging
}
func (envvolume *EnvVolume) GetSeed() string {
	return envvolume.Seed
}

func (envvolume *EnvVolume) SetSeed(Seed string) *EnvVolume {
	envvolume.Seed = Seed
	return envvolume
}
func (workloadvolume *WorkloadVolume) GetSeed() string {
	return workloadvolume.Seed
}

func (workloadvolume *WorkloadVolume) GetFilesystem() *string {
	return workloadvolume.Filesystem
}

func (workloadvolume *WorkloadVolume) GetMount() *string {
	return workloadvolume.Mount
}

func (workloadvolume *WorkloadVolume) SetSeed(Seed string) *WorkloadVolume {
	workloadvolume.Seed = Seed
	return workloadvolume
}

func (workloadvolume *WorkloadVolume) SetFilesystem(Filesystem *string) *WorkloadVolume {
	workloadvolume.Filesystem = Filesystem
	return workloadvolume
}

func (workloadvolume *WorkloadVolume) SetMount(Mount *string) *WorkloadVolume {
	workloadvolume.Mount = Mount
	return workloadvolume
}
func (credential *Credential) GetUsername() string {
	return credential.Username
}

func (credential *Credential) GetPassword() string {
	return credential.Password
}

func (credential *Credential) SetUsername(Username string) *Credential {
	credential.Username = Username
	return credential
}

func (credential *Credential) SetPassword(Password string) *Credential {
	credential.Password = Password
	return credential
}
func (compose *Compose) GetArchive() string {
	return compose.Archive
}

func (compose *Compose) SetArchive(Archive string) *Compose {
	compose.Archive = Archive
	return compose
}
func (play *Play) GetArchive() string {
	return play.Archive
}

func (play *Play) SetArchive(Archive string) *Play {
	play.Archive = Archive
	return play
}
func (workload *Workload) GetType() string {
	return workload.Type
}

func (workload *Workload) GetVolumes() WorkloadVolumes {
	return workload.Volumes
}

func (workload *Workload) GetAuths() Auths {
	return workload.Auths
}

func (workload *Workload) GetEnv() ENV.Env {
	return workload.Env
}

func (workload *Workload) GetCompose() *Compose {
	return workload.Compose
}

func (workload *Workload) GetPlay() *Play {
	return workload.Play
}

func (workload *Workload) GetImages() *Images {
	return workload.Images
}

func (workload *Workload) GetConfidentialContainers() any {
	return workload.ConfidentialContainers
}

func (workload *Workload) SetType(Type string) *Workload {
	workload.Type = Type
	return workload
}

func (workload *Workload) SetVolumes(Volumes WorkloadVolumes) *Workload {
	workload.Volumes = Volumes
	return workload
}

func (workload *Workload) SetAuths(Auths Auths) *Workload {
	workload.Auths = Auths
	return workload
}

func (workload *Workload) SetEnv(Env ENV.Env) *Workload {
	workload.Env = Env
	return workload
}

func (workload *Workload) SetCompose(Compose *Compose) *Workload {
	workload.Compose = Compose
	return workload
}

func (workload *Workload) SetPlay(Play *Play) *Workload {
	workload.Play = Play
	return workload
}

func (workload *Workload) SetImages(Images *Images) *Workload {
	workload.Images = Images
	return workload
}

func (workload *Workload) SetConfidentialContainers(ConfidentialContainers any) *Workload {
	workload.ConfidentialContainers = ConfidentialContainers
	return workload
}
func (env *Env) GetType() string {
	return env.Type
}

func (env *Env) GetLogging() *Logging {
	return env.Logging
}

func (env *Env) GetVolumes() EnvVolumes {
	return env.Volumes
}

func (env *Env) GetEnv() ENV.Env {
	return env.Env
}

func (env *Env) GetSigningKey() *string {
	return env.SigningKey
}

func (env *Env) GetConfidentialContainers() any {
	return env.ConfidentialContainers
}

func (env *Env) SetType(Type string) *Env {
	env.Type = Type
	return env
}

func (env *Env) SetLogging(Logging *Logging) *Env {
	env.Logging = Logging
	return env
}

func (env *Env) SetVolumes(Volumes EnvVolumes) *Env {
	env.Volumes = Volumes
	return env
}

func (env *Env) SetEnv(Env ENV.Env) *Env {
	env.Env = Env
	return env
}

func (env *Env) SetSigningKey(SigningKey *string) *Env {
	env.SigningKey = SigningKey
	return env
}

func (env *Env) SetConfidentialContainers(ConfidentialContainers any) *Env {
	env.ConfidentialContainers = ConfidentialContainers
	return env
}

func (contract *Contract) GetWorkload() *Workload {
	return contract.Workload
}

func (contract *Contract) GetEnv() *Env {
	return contract.Env
}

func (contract *Contract) GetAttestationPublicKey() *string {
	return contract.AttestationPublicKey
}

func (contract *Contract) GetEnvWorkloadSignature() *string {
	return contract.EnvWorkloadSignature
}

func (contract *Contract) SetWorkload(Workload *Workload) *Contract {
	contract.Workload = Workload
	return contract
}

func (contract *Contract) SetEnv(Env *Env) *Contract {
	contract.Env = Env
	return contract
}

func (contract *Contract) SetAttestationPublicKey(AttestationPublicKey *string) *Contract {
	contract.AttestationPublicKey = AttestationPublicKey
	return contract
}

func (contract *Contract) SetEnvWorkloadSignature(EnvWorkloadSignature *string) *Contract {
	contract.EnvWorkloadSignature = EnvWorkloadSignature
	return contract
}

func (dockercontenttrust *DockerContentTrust) GetNotary() string {
	return dockercontenttrust.Notary
}

func (dockercontenttrust *DockerContentTrust) GetPublicKey() string {
	return dockercontenttrust.PublicKey
}

func (dockercontenttrust *DockerContentTrust) SetNotary(Notary string) *DockerContentTrust {
	dockercontenttrust.Notary = Notary
	return dockercontenttrust
}

func (dockercontenttrust *DockerContentTrust) SetPublicKey(PublicKey string) *DockerContentTrust {
	dockercontenttrust.PublicKey = PublicKey
	return dockercontenttrust
}
func (redhatsigning *RedHatSigning) GetPublicKey() string {
	return redhatsigning.PublicKey
}

func (redhatsigning *RedHatSigning) SetPublicKey(PublicKey string) *RedHatSigning {
	redhatsigning.PublicKey = PublicKey
	return redhatsigning
}
func (images *Images) GetDockerContentTrust() DockerContentTrusts {
	return images.DockerContentTrust
}

func (images *Images) GetRedHatSigning() RedHatSignings {
	return images.RedHatSigning
}

func (images *Images) SetDockerContentTrust(DockerContentTrust DockerContentTrusts) *Images {
	images.DockerContentTrust = DockerContentTrust
	return images
}

func (images *Images) SetRedHatSigning(RedHatSigning RedHatSignings) *Images {
	images.RedHatSigning = RedHatSigning
	return images
}
