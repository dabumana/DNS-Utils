package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type IoCList struct {
	Data []data `json:"data"`
}

type data struct {
	Artifact string `json:"artifact"`
	Type     string `json:"artifact_type"`
	Date     string `json:"created_date"`
	RefLink  string `json:"reference_link"`
	RefTxt   string `json:"reference_text"`
}

func main() {
	resp, err := http.Get("https://labs.inquest.net/api/iocdb/list")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	iocList := IoCList{}
	err = json.Unmarshal(body, &iocList)
	if err != nil {
		fmt.Println(err)
		return
	}

	rules := []string{}
	for _, value := range iocList.Data {
		if value.Artifact != "" && value.Type == "domain" || value.Type == "url" {
			rule := fmt.Sprintf("alert ip any any -> %s any (msg:\"Potential IOC detected of TYPE %s reference %s\"; sid:1000001; rev:1;)\n", value.Artifact, value.Type, value.RefLink)
			rules = append(rules, rule)
		}
	}

	filePath := "inbound.rules"
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed creating file: %s", err)
	}

	for _, f := range rules {
		_, err = file.WriteString(f)
		if err != nil {
			log.Fatalf("Failed writing the rule content: %s", err)
		}
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatalf("Failed closing file: %s", err)
		}
	}(file)

	log.Printf("File created: %s", filePath)
}
