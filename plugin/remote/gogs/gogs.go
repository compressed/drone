package gogs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/drone/drone/shared/model"
)

const (
	droneYmlUrlPattern = "%s/raw/%s/.drone.yml"
)

type Gogs struct {
	Url    string
	Secret string
}

func New(url string, secret string) *Gogs {
	return &Gogs{Url: url, Secret: secret}
}

// Authorize handles Bitbucket API Authorization
func (r *Gogs) Authorize(res http.ResponseWriter, req *http.Request) (*model.Login, error) {
	var username = req.FormValue("username")
	var email = req.FormValue("email")

	var login = new(model.Login)
	login.Name = username
	login.Email = email
	login.Login = username
	return login, nil
}

// GetKind returns the internal identifier of this remote Bitbucket instane.
func (r *Gogs) GetKind() string {
	return model.RemoteGogs
}

// GetHost returns the hostname of this remote Bitbucket instance.
func (r *Gogs) GetHost() string {
	uri, _ := url.Parse(r.Url)
	return uri.Host
}

// GetRepos fetches all repositories that the specified
// user has access to in the remote system.
func (r *Gogs) GetRepos(user *model.User) ([]*model.Repo, error) {
	var repos []*model.Repo

	var remote = r.GetKind()

	doc, err := goquery.NewDocument(r.Url + "/user/" + user.Login)
	if err != nil {
		log.Fatal(err)
	}

	// user or org
	fmt.Println(doc.Url)

	userType := strings.Split(doc.Url.Path, "/")[1]

	fmt.Println("UserType=" + userType)

	var repoUrls []string
	if userType == "org" {
		doc.Find(".org-repo-item h2 a").Each(func(i int, s *goquery.Selection) {
			repoUrl, _ := s.Attr("href")
			fmt.Printf("%s\n", repoUrl)
			repoUrls = append(repoUrls, repoUrl)
		})
	} else if userType == "user" {
		doc.Find(".repo-list li h4 a").Each(func(i int, s *goquery.Selection) {
			repoUrl, _ := s.Attr("href")
			fmt.Printf("%s\n", repoUrl)
			repoUrls = append(repoUrls, repoUrl)
		})
	} else {
		return repos, fmt.Errorf("Unable to determine user type")
	}

	for _, repoUrl := range repoUrls {
		var repoParts = strings.Split(repoUrl, "/")
		// TODO: can only fetch repos that belong to the user
		// not all the repos the user has access to
		// if
		var owner = repoParts[1]
		var name = repoParts[2]

		repoDoc, err := goquery.NewDocument(r.Url + repoUrl)
		if err != nil {
			fmt.Errorf("Unable to fetch repo page:" + r.Url + repoUrl)
		}

		ssh, found := (repoDoc.Find("#repo-clone-ssh").First()).Attr("data-link")
		if !found {
			fmt.Errorf("Unable to fetch ssh on:" + r.Url + repoUrl)
		}

		clone, found := (repoDoc.Find("#repo-clone-https").First()).Attr("data-link")
		if !found {
			fmt.Errorf("Unable to fetch clone on:" + r.Url + repoUrl)
		}

		var repo = model.Repo{
			UserID:   user.ID,
			Remote:   remote,
			Host:     r.GetHost(),
			Owner:    owner,
			Name:     name,
			Private:  false, // TODO: only possible to support public repos for now
			CloneURL: clone,
			GitURL:   clone,
			SSHURL:   ssh,
			URL:      r.Url + repoUrl,
			Role: &model.Perm{
				Admin: true,
				Write: true,
				Read:  true,
			},
		}

		repos = append(repos, &repo)
	}

	return repos, err
}

// GetScript fetches the build script (.drone.yml) from the remote
// repository and returns a byte array
func (r *Gogs) GetScript(user *model.User, repo *model.Repo, hook *model.Hook) ([]byte, error) {
	// GET .drone.yml file
	droneYmlUrl := fmt.Sprintf(droneYmlUrlPattern, repo.URL, hook.Sha)
	println("droneYmlUrl is ", droneYmlUrl)
	ymlGetResponse, err := http.Get(droneYmlUrl)
	if err != nil {
		println(err.Error())
		return nil, err
	} else {
		defer ymlGetResponse.Body.Close()
		yml, err := ioutil.ReadAll(ymlGetResponse.Body)
		if err != nil {
			println(err.Error())
			return nil, err
		}
		return yml, err
	}
}

// Activate activates a repository by adding a Post-commit hook and
// a Public Deploy key, if applicable.
func (r *Gogs) Activate(user *model.User, repo *model.Repo, link string) error {
	/*var client = bitbucket.New(
		r.Client,
		r.Secret,
		user.Access,
		user.Secret,
	)

	// parse the hostname from the hook, and use this
	// to name the ssh key
	var hookurl, err = url.Parse(link)
	if err != nil {
		return err
	}

	// if the repository is private we'll need
	// to upload a github key to the repository
	if repo.Private {
		// name the key
		var keyname = "drone@" + hookurl.Host
		var _, err = client.RepoKeys.CreateUpdate(repo.Owner, repo.Name, repo.PublicKey, keyname)
		if err != nil {
			return err
		}
	}

	// add the hook
	_, err = client.Brokers.CreateUpdate(repo.Owner, repo.Name, link, bitbucket.BrokerTypePost)
	return err*/
	return nil
}

type PayloadAuthor struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	UserName string `json:"username"`
}
type PayloadCommit struct {
	Id      string         `json:"id"`
	Message string         `json:"message"`
	Url     string         `json:"url"`
	Author  *PayloadAuthor `json:"author"`
}
type PayloadRepo struct {
	Id          int64          `json:"id"`
	Name        string         `json:"name"`
	Url         string         `json:"url"`
	Description string         `json:"description"`
	Website     string         `json:"website"`
	Watchers    int            `json:"watchers"`
	Owner       *PayloadAuthor `json:"owner"`
	Private     bool           `json:"private"`
}

// Payload represents payload information of payload.
type Payload struct {
	Secret  string           `json:"secret"`
	Ref     string           `json:"ref"`
	Commits []*PayloadCommit `json:"commits"`
	Repo    *PayloadRepo     `json:"repository"`
	Pusher  *PayloadAuthor   `json:"pusher"`
}

var ErrInvalidReceiveHook = errors.New("Invalid JSON payload received over webhook")

func ParseHook(raw []byte) (*Payload, error) {
	hook := Payload{}
	if err := json.Unmarshal(raw, &hook); err != nil {
		return nil, err
	}
	// it is possible the JSON was parsed, however,
	// was not from Github (maybe was from Bitbucket)
	// So we'll check to be sure certain key fields
	// were populated
	switch {
	case hook.Repo == nil:
		return nil, ErrInvalidReceiveHook
	case len(hook.Ref) == 0:
		return nil, ErrInvalidReceiveHook
	}
	return &hook, nil
}

func (h *Payload) Branch() string {
	return strings.Replace(h.Ref, "refs/heads/", "", -1)
}

// ParseHook parses the post-commit hook from the Request body
// and returns the required data in a standard format.
func (r *Gogs) ParseHook(req *http.Request) (*model.Hook, error) {
	defer req.Body.Close()
	var payloadbytes, _ = ioutil.ReadAll(req.Body)
	var payload, err = ParseHook(payloadbytes)
	if err != nil {
		return nil, err
	}

	// verify the payload has the minimum amount of required data.
	if payload.Repo == nil || payload.Commits == nil || len(payload.Commits) == 0 {
		return nil, fmt.Errorf("Invalid Gogs post-commit Hook. Missing Repo or Commit data.")
	}

	if payload.Secret != r.Secret {
		return nil, fmt.Errorf("Payload secret does not match stored secret")
	}

	return &model.Hook{
		Owner:     payload.Repo.Owner.UserName,
		Repo:      payload.Repo.Name,
		Sha:       payload.Commits[0].Id,
		Branch:    payload.Branch(),
		Author:    payload.Commits[0].Author.UserName,
		Timestamp: time.Now().UTC().String(),
		Message:   payload.Commits[0].Message,
	}, nil
}
