package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const dbName = "./domains.db"

var avaliableChars []rune

const detectURL = "https://checkapi.aliyun.com/check/checkdomain?domain=%s.%s&command=&token=Y"

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
	fmt.Println(m...)
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
		fmt.Println("redetect: redo all detect")
		return
	}
	event := os.Args[1]
	if event == "prepare" {
		minLen := 2
		maxLen := 3
		initDatatable()
		for i := minLen; i <= maxLen; i++ {
			prepareMaterials(getDomainList(i))
		}
	} else if event == "redetect" {
		page := 1
		pageLen := 100
		for {
			db, err := connDatabase()
			if err != nil {
				return
			}
			rows, err := db.Query("SELECT id, name, suffix FROM domains ORDER BY id LIMIT ? OFFSET ?", pageLen, (page-1)*pageLen)
			if err != nil {
				log(err)
			}
			type domainInfo struct {
				id     int
				name   string
				suffix string
			}
			domainInfos := []domainInfo{}
			count := 0
			for rows.Next() {
				count++
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
			log(count)
			db.Close()
			page++
			if count < pageLen {
				break
			}
		}
	}
}
