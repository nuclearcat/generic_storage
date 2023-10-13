Generic HTTP storage

## Usage

```shell
./generic_storage -cfg config.yaml -port 8080
```

## Configuration

```yaml
users:
  - username: user1
    token: 10BPPnSSqGzsX7WF

  - username: user2
    token: 10BPPnSSqGzsX7W1

filedir: ./files

```
User files will be stored at filedir + username, means in this example:
- user1 files will be stored at ./files/user1 directory, and
- user2 files will be stored at ./files/user2 directory

## API

### Upload file

```shell
curl -X POST -H "Authorization: Bearer 10BPPnSSqGzsX7W1" -F file0=@1/bug_reproduce.zip http://host:port/upload
```

### Download file

url: http://host:port/username/path/filename

You can browse the file list at http://host:port/username

## License
