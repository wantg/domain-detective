package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var avaliableChars []rune

const dbName = "./domains.db"
const detectURL = "https://checkapi.aliyun.com/check/checkdomain?domain=%s.%s&command=&token=Y"
const logFile = "./runtime.log"

func init() {
	for i := '0'; i <= '9'; i++ {
		avaliableChars = append(avaliableChars, i)
	}
	for i := 'a'; i <= 'z'; i++ {
		avaliableChars = append(avaliableChars, i)
	}
}

func getDomainList(size int) [][]rune {
	ra := [][]rune{}
	for _, c1 := range avaliableChars {
		if size > 1 {
			for _, c2 := range avaliableChars {
				if size > 2 {
					for _, c3 := range avaliableChars {
						if size > 3 {
							for _, c4 := range avaliableChars {
								if size > 4 {
									for _, c5 := range avaliableChars {
										ra = append(ra, []rune{c1, c2, c3, c4, c5})
									}
								} else {
									ra = append(ra, []rune{c1, c2, c3, c4})
								}
							}
						} else {
							ra = append(ra, []rune{c1, c2, c3})
						}
					}
				} else {
					ra = append(ra, []rune{c1, c2})
				}
			}
		} else {
			ra = append(ra, []rune{c1})
		}
	}
	return ra
}

func log(msg ...interface{}) {
	m := []interface{}{time.Now().Format("[2006-01-02 15:04:05]")}
	m = append(m, msg...)
	logFileExt := filepath.Ext(logFile)
	logFileBaseName := strings.TrimSuffix(logFile, logFileExt)
	logFilePath := logFileBaseName + "-" + time.Now().Format("2006-01-02") + logFileExt
	f, _ := os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintln(m...))
}

func connDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbName)
	if err != nil {
		log(err)
	}
	return db, err
}

func runPrepareExec(db *sql.DB, sql string, args ...interface{}) (sql.Result, error) {
	stmt, err := db.Prepare(sql)
	if err != nil {
		log(err)
		return nil, err
	}
	result, err := stmt.Exec(args...)
	if err != nil {
		log(err)
	}
	return result, err
}

func initDatatable() {
	os.Remove(dbName)
	db, err := connDatabase()
	if err != nil {
		return
	}
	defer db.Close()
	runPrepareExec(db, `DROP TABLE IF EXISTS domains`)
	runPrepareExec(db, `
		CREATE TABLE domains (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       VARCHAR(64),
			len        INT,
			suffix 	   VARCHAR(64),
			status     INT NULL,
			result     VARCHAR(200) NULL,
			created_at DATE,
			updated_at DATE NULL
		)`)
	runPrepareExec(db, `CREATE INDEX domains_idx_status ON domains(status);`)
}

func prepareMaterials(ra [][]rune) {
	log("prepare", string(ra[0]), "to", string(ra[len(ra)-1]))
	db, err := connDatabase()
	if err != nil {
		return
	}
	defer db.Close()
	if err != nil {
		log(err)
	}
	for _, s := range ra {
		// log(i, string(s))
		runPrepareExec(db, "INSERT INTO domains(name, len, suffix, created_at) values(?,?,?,?)",
			string(s), len(s), "com", time.Now())
	}
}

func main() {
	// os.Args = []string{"", "prepare"}
	if len(os.Args) < 2 {
		fmt.Println("what u want? send command line arg to me")
		fmt.Println("prepare: recreate database and prepare domains to detect")
		fmt.Println("detect: detect with aliyun")
		return
	}
	event := os.Args[1]
	if event == "prepare" {
		initDatatable()
		minLen := 2
		maxLen := 5
		for i := minLen; i <= maxLen; i++ {
			sqlFile := fmt.Sprintf("c-%d.sql", i)
			os.Remove(sqlFile)
			ra := getDomainList(i)
			f, _ := os.OpenFile(sqlFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
			for idx, s := range ra {
				if idx%100000 == 0 {
					log(i, string(s))
				}
				f.WriteString(fmt.Sprintf(
					"INSERT INTO domains(name, len, suffix, created_at) values('%s',%d,'%s','%s');\n",
					string(s), len(s), "com", time.Now().Format("2006-01-02 15:04:05"),
				))
			}
			f.Close()
		}
	} else if event == "detect" {
		page := 1
		pageLen := 100
		for {
			db, err := connDatabase()
			if err != nil {
				break
			}
			rows, err := db.Query("SELECT id, name, suffix FROM domains WHERE status is null ORDER BY id LIMIT ? OFFSET ?", pageLen, (page-1)*pageLen)
			if err != nil {
				log(err)
				break
			}
			type domainInfo struct {
				id     int
				name   string
				suffix string
			}
			domainInfos := []domainInfo{}
			for rows.Next() {
				di := domainInfo{}
				err := rows.Scan(&di.id, &di.name, &di.suffix)
				if err != nil {
					log(err)
					continue
				}
				domainInfos = append(domainInfos, di)
			}
			rows.Close()
			for _, di := range domainInfos {
				url := fmt.Sprintf(detectURL, di.name, di.suffix)
				resp, err := http.Get(url)
				if err != nil {
					log(err)
					continue
				}
				bts, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					log(err)
					continue
				}
				type detectResult struct {
					ErrorCode int64 `json:"errorCode"`
					Module    []struct {
						Avail int    `json:"avail"`
						Name  string `json:"name"`
						Tld   string `json:"tld"`
					} `json:"module"`
					Success string `json:"success"`
				}
				dr := detectResult{}
				json.Unmarshal(bts, &dr)
				sql := "UPDATE domains set result = ?, updated_at = ? where id = ?"
				args := []interface{}{string(bts), time.Now(), di.id}
				if len(dr.Module) > 0 {
					sql = "UPDATE domains set status = ?, result = ?, updated_at = ? where id = ?"
					args = []interface{}{dr.Module[0].Avail, string(bts), time.Now(), di.id}
				}
				_, err = runPrepareExec(db, sql, args...)
				if err != nil {
					log(err)
				}
			}
			count := len(domainInfos)
			if count > 0 {
				log(domainInfos[0].name + " - " + domainInfos[count-1].name)
			}
			log(count)
			db.Close()
			page++
			if count < pageLen {
				break
			}
		}
	}
}
