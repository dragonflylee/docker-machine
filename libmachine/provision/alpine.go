package provision

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/docker/machine/libmachine/auth"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/provision/pkgaction"
	"github.com/docker/machine/libmachine/provision/serviceaction"
	"github.com/docker/machine/libmachine/swarm"
)

func init() {
	Register("Alpine", &RegisteredProvisioner{
		New: NewAlpineProvisioner,
	})
}

type AlpineProvisioner struct {
	GenericProvisioner
}

func (p *AlpineProvisioner) String() string {
	return "alpine"
}

func NewAlpineProvisioner(d drivers.Driver) Provisioner {
	return &AlpineProvisioner{
		GenericProvisioner{
			SSHCommander:      GenericSSHCommander{Driver: d},
			DockerOptionsDir:  "/etc/docker",
			DaemonOptionsFile: "/etc/conf.d/docker",
			OsReleaseID:       "alpine",
			Driver:            d,
		},
	}
}

func (p *AlpineProvisioner) GenerateDockerOptions(dockerPort int) (*DockerOptions, error) {
	var (
		engineCfg bytes.Buffer
	)

	driverNameLabel := fmt.Sprintf("provider=%s", p.Driver.DriverName())
	p.EngineOptions.Labels = append(p.EngineOptions.Labels, driverNameLabel)

	engineConfigTmpl := `DOCKER_OPTS=\"-H tcp://0.0.0.0:{{.DockerPort}} -H unix:///var/run/docker.sock --storage-driver {{.EngineOptions.StorageDriver}} --tlsverify --tlscacert {{.AuthOptions.CaCertRemotePath}} --tlscert {{.AuthOptions.ServerCertRemotePath}} --tlskey {{.AuthOptions.ServerKeyRemotePath}} {{ range .EngineOptions.Labels }}--label {{.}} {{ end }}{{ range .EngineOptions.InsecureRegistry }}--insecure-registry {{.}} {{ end }}{{ range .EngineOptions.RegistryMirror }}--registry-mirror {{.}} {{ end }}{{ range .EngineOptions.ArbitraryFlags }}--{{.}} {{ end }}\"`
	t, err := template.New("engineConfig").Parse(engineConfigTmpl)
	if err != nil {
		return nil, err
	}

	engineConfigContext := EngineConfigContext{
		DockerPort:    dockerPort,
		AuthOptions:   p.AuthOptions,
		EngineOptions: p.EngineOptions,
	}

	t.Execute(&engineCfg, engineConfigContext)

	return &DockerOptions{
		EngineOptions:     engineCfg.String(),
		EngineOptionsPath: p.DaemonOptionsFile,
	}, nil
}

func (provisioner *AlpineProvisioner) Package(name string, action pkgaction.PackageAction) error {
	var packageAction string

	updateMetadata := true

	switch action {
	case pkgaction.Install, pkgaction.Upgrade:
		packageAction = "add"
	case pkgaction.Remove, pkgaction.Purge:
		packageAction = "del"
		updateMetadata = false
	}

	if updateMetadata {
		if err := waitForLock(provisioner, "sudo apk update"); err != nil {
			return err
		}
	}

	command := fmt.Sprintf("sudo apk %s %s", packageAction, name)

	log.Debugf("package: action=%s name=%s", action.String(), name)

	return waitForLock(provisioner, command)
}

func (p *AlpineProvisioner) Service(name string, action serviceaction.ServiceAction) error {

	var command string

	switch action {
	case serviceaction.Start, serviceaction.Stop, serviceaction.Restart:
		command = fmt.Sprintf("sudo rc-service %s %s", name, action)
	case serviceaction.Enable:
		command = fmt.Sprintf("sudo rc-update add %s", name)
	case serviceaction.Disable:
		command = fmt.Sprintf("sudo rc-update del %s", name)
	default:
		return nil
	}

	if _, err := p.SSHCommand(command); err != nil {
		return err
	}
	return nil
}

func (provisioner *AlpineProvisioner) Provision(swarmOptions swarm.Options, authOptions auth.Options, engineOptions engine.Options) error {
	provisioner.SwarmOptions = swarmOptions
	provisioner.AuthOptions = authOptions
	provisioner.EngineOptions = engineOptions
	swarmOptions.Env = engineOptions.Env

	storageDriver, err := decideStorageDriver(provisioner, "overlay2", engineOptions.StorageDriver)
	if err != nil {
		return err
	}
	provisioner.EngineOptions.StorageDriver = storageDriver

	// HACK: since debian does not come with sudo by default we install
	log.Debug("installing sudo")
	if _, err := provisioner.SSHCommand("if ! type sudo; then apk add sudo; fi"); err != nil {
		return err
	}

	log.Debug("setting hostname")
	if err := provisioner.SetHostname(provisioner.Driver.GetMachineName()); err != nil {
		return err
	}

	log.Debug("installing docker")
	if err = provisioner.Package("docker", pkgaction.Install); err != nil {
		return err
	}
	if err = provisioner.Service("docker", serviceaction.Restart); err != nil {
		return err
	}
	if err = provisioner.Service("docker", serviceaction.Enable); err != nil {
		return err
	}

	log.Debug("waiting for docker daemon")
	if err := mcnutils.WaitFor(provisioner.dockerDaemonResponding); err != nil {
		return err
	}

	provisioner.AuthOptions = setRemoteAuthOptions(provisioner)

	log.Debug("configuring auth")
	if err := ConfigureAuth(provisioner); err != nil {
		return err
	}

	log.Debug("configuring swarm")
	if err := configureSwarm(provisioner, swarmOptions, provisioner.AuthOptions); err != nil {
		return err
	}

	// enable in systemd
	log.Debug("enabling docker in systemd")
	err = provisioner.Service("docker", serviceaction.Enable)
	return err
}

func (provisioner *AlpineProvisioner) dockerDaemonResponding() bool {
	log.Debug("checking docker daemon")

	if out, err := provisioner.SSHCommand("sudo docker version"); err != nil {
		log.Warnf("Error getting SSH command to check if the daemon is up: %s", err)
		log.Debugf("'sudo docker version' output:\n%s", out)
		return false
	}

	// The daemon is up if the command worked.  Carry on.
	return true
}
