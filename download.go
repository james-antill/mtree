package main

import (
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"fmt"
	"net"
	"os"
	"os/user"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	roc "github.com/james-antill/rename-on-close"
	"github.com/pkg/sftp"
)

func dliSSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err ==
		nil {

		client := agent.NewClient(sshAgent)

		signers, err := client.Signers()
		if err != nil {
			// fmt.Println("signers:", err)
			return nil
		}

		authm := ssh.PublicKeys(signers...)
		if authm == nil {
			// fmt.Println("authm is nil")
		}
		return authm
		// return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func dlSetup(mtr *MTRoot, progress bool) error {
	purl, err := url.Parse(mtr.Conf.Remote.URL)
	if err != nil {
		return err
	}

	switch purl.Scheme {
	case "https":
		fallthrough
	case "http":
		mtr.Conf.Remote.dlType = "http"
		return nil

	case "sftp":
		mtr.Conf.Remote.dlType = "sftp"
		break

	case "ssh":
		fallthrough
	case "scp":
		fallthrough
	default:
		return fmt.Errorf("Invalid URL scheme: %s", purl.Scheme)
	}

	dlUser := mtr.Conf.Remote.User
	lUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get user: %s", err)
	}
	if dlUser == "" {
		dlUser = lUser.Name
	}

	hkcb, err := knownhosts.New(lUser.HomeDir + "/.ssh/known_hosts")
	if err != nil {
		return fmt.Errorf("Failed to get known_hosts: %s", err)
	}
	authMeths := []ssh.AuthMethod{dliSSHAgent()}

	config := &ssh.ClientConfig{
		User:            dlUser,
		Auth:            authMeths,
		HostKeyCallback: hkcb,
	}
	config.SetDefaults()
	host := purl.Host
	if strings.IndexByte(host, ':') == -1 {
		host += ":22"
	}

	conn, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return fmt.Errorf("Failed to dial: %v", err)
	}
	//defer conn.Close()
	crfs, err := sftp.NewClient(conn, sftp.MaxPacket(1<<15))
	if err != nil {
		return fmt.Errorf("Failed to create sftp client: %v", err)
	}
	//defer crfs.Close()

	mtr.Conf.Remote.dlSSH = conn
	mtr.Conf.Remote.dlSFTP = crfs
	return nil
}

func dlClose(mtr *MTRoot) {
	conn := mtr.Conf.Remote.dlSSH
	if conn != nil {
		conn.Close()
	}
	mtr.Conf.Remote.dlSSH = nil

	crfs := mtr.Conf.Remote.dlSFTP
	if crfs != nil {
		crfs.Close()
	}
	mtr.Conf.Remote.dlSFTP = nil
}

func dlFile(mtr *MTRoot, dlpath, rfname string) error {
	// download mtr.Conf.Remote.URL + rfname to dlpath
	fo, err := roc.Create(dlpath + "/" + path.Base(rfname))
	if err != nil {
		return err
	}
	defer fo.Close()

	switch mtr.Conf.Remote.dlType {
	case "http":
		resp, err := http.Get(mtr.Conf.Remote.URL + "/" + rfname)
		if err != nil {
			return fmt.Errorf("http.Open: %v\n", err)
			return err
		}
		defer resp.Body.Close()

		// bar := p.AddBarDef(size, name, decor.Unit_KiB)
		//        reader := bar.ProxyReader(resp.Body)
		if _, err := io.Copy(fo, resp.Body); err != nil {
			return fmt.Errorf("http.Copy: %v\n", err)
		}

	case "sftp":
		purl, _ := url.Parse(mtr.Conf.Remote.URL)
		crfs := mtr.Conf.Remote.dlSFTP

		rfname = purl.Path[1:] + "/" + rfname
		r, err := crfs.Open(rfname)
		if err != nil {
			return fmt.Errorf("sftp.Open(%s): %v\n", rfname, err)
		}
		defer r.Close()

		if _, err := io.Copy(fo, r); err != nil {
			return fmt.Errorf("sftp.Copy(%s): %v\n", rfname, err)
		}
	}

	if err := fo.CloseRename(); err != nil {
		return err
	}

	return nil

}
