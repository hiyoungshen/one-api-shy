package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"one-api/common"
	"one-api/model"
	"strings"
	"time"
    "regexp" // added by shy
	"os" // added by shy
)

// added by shy
type ResponseData struct {
	SourceCode       string `json:"source_code"`
	ProblemInfo      ProblemInfoData `json:"problem_info"`
	Status           string `json:"status"`
	Username         string `json:"username"`
	Language         string `json:"language"`
}
type ProblemInfoData struct {
	ProblemDescription       string `json:"problem_description"`
	InputDescription         string `json:"input_description"`
	OutputDescription        string `json:"output_description"`
	SampleInputDescription   string `json:"sample_input_description"`
	SampleOutputDescription  string `json:"sample_output_description"`
}


const (
	APITypeOpenAI = iota
	APITypeClaude
	APITypePaLM
	APITypeBaidu
	APITypeZhipu
	APITypeAli
	APITypeXunfei
	APITypeAIProxyLibrary
)

var httpClient *http.Client
var impatientHTTPClient *http.Client

func init() {
	httpClient = &http.Client{}
	impatientHTTPClient = &http.Client{
		Timeout: 5 * time.Second,
	}
}

// added by shy
func modifyRequestBody(c *gin.Context, textRequest GeneralOpenAIRequest) {
	newRequestBody, _ := json.Marshal(textRequest)
	newRequest, _ := http.NewRequest(c.Request.Method, c.Request.URL.String(), bytes.NewBuffer(newRequestBody))
	for key, values := range c.Request.Header {
		for _, value := range values {
			newRequest.Header.Add(key, value)
		}
	}
	c.Request = newRequest
}

func relayTextHelper(c *gin.Context, relayMode int) *OpenAIErrorWithStatusCode {
	channelType := c.GetInt("channel")
	tokenId := c.GetInt("token_id")
	userId := c.GetInt("id")
	consumeQuota := c.GetBool("consume_quota")
	group := c.GetString("group")
	
	var textRequest GeneralOpenAIRequest
	if consumeQuota || channelType == common.ChannelTypeAzure || channelType == common.ChannelTypePaLM {
		err := common.UnmarshalBodyReusable(c, &textRequest)
		if err != nil {
			return errorWrapper(err, "bind_request_body_failed", http.StatusBadRequest)
		}
	}
	if relayMode == RelayModeModerations && textRequest.Model == "" {
		textRequest.Model = "text-moderation-latest"
	}
	if relayMode == RelayModeEmbeddings && textRequest.Model == "" {
		textRequest.Model = c.Param("model")
	}
	// request validation
	if textRequest.Model == "" {
		return errorWrapper(errors.New("model is required"), "required_field_missing", http.StatusBadRequest)
	}
	switch relayMode {
	case RelayModeCompletions:
		if textRequest.Prompt == "" {
			return errorWrapper(errors.New("field prompt is required"), "required_field_missing", http.StatusBadRequest)
		}
	case RelayModeChatCompletions:
		if textRequest.Messages == nil || len(textRequest.Messages) == 0 {
			return errorWrapper(errors.New("field messages is required"), "required_field_missing", http.StatusBadRequest)
		}
	case RelayModeEmbeddings:
	case RelayModeModerations:
		if textRequest.Input == "" {
			return errorWrapper(errors.New("field input is required"), "required_field_missing", http.StatusBadRequest)
		}
	case RelayModeEdits:
		if textRequest.Instruction == "" {
			return errorWrapper(errors.New("field instruction is required"), "required_field_missing", http.StatusBadRequest)
		}
	}
	
	// added by shy
	for key := range textRequest.Messages {
		if textRequest.Messages[key].Role == "user" {
			// 正则表达式匹配“匹配形如http://wjpython.openjudge.cn/xxxx到结尾”的字符串
			pattern := `http://wjpython.openjudge.cn/.*$`
			input := textRequest.Messages[key].Content
			regex, _ := regexp.Compile(pattern)
			match := regex.FindString(input)
			if match != "" {
				resp, err := http.Post("http://localhost:3002/", "application/json", bytes.NewBuffer([]byte(`{"url": "` + match + `"}`)))

				if err != nil {
					return errorWrapper(err, "do_request_failed", http.StatusInternalServerError)
				} else {
					var resp_dict ResponseData
					err := json.NewDecoder(resp.Body).Decode(&resp_dict)
					if err != nil {
						return errorWrapper(err, "decode_response_failed", http.StatusInternalServerError)
					}
					source_code := resp_dict.SourceCode
					problem_description := resp_dict.ProblemInfo.ProblemDescription
					input_description := resp_dict.ProblemInfo.InputDescription
					output_description := resp_dict.ProblemInfo.OutputDescription
					sample_input_description := resp_dict.ProblemInfo.SampleInputDescription
					sample_output_description := resp_dict.ProblemInfo.SampleOutputDescription
					status := resp_dict.Status
					// username := resp_dict.Username
					// language := resp_dict.Language
					// User的消息改为预先定义的Prompt格式
					textRequest.Messages[key].Content = "我希望你假定自己是一个擅长在线编程解题的人，你将解释OpenJudge提交的错误原因。用户会给你一个OpenJudge的提交记录，包括题目描述、样例的描述、用户的代码和用户代码的提交状态（提交状态可能是Accepted、Runtime Error等等），你需要解释这个提交为什么会出错。你需要解释的内容包括：\n1. 代码的错误原因\n2. 代码的改进方案\n3. 代码的改进后的样子，并为每一行添加注释\n\n请在回答中写出以上三点，不要写解释。" + "\n\n题目描述：" + problem_description + "\n输入描述：" + input_description + "\n输出描述：" + output_description + "\n样例输入：" + sample_input_description + "\n样例输出：" + sample_output_description + "\n用户提交的源代码：" + source_code + "\n提交状态：" + status + "\n\n 你的回答：\n"
				}
			} else {
			}
		}
	}
	modifyRequestBody(c, textRequest)

	// map model name
	modelMapping := c.GetString("model_mapping")
	isModelMapped := false
	if modelMapping != "" && modelMapping != "{}" {
		modelMap := make(map[string]string)
		err := json.Unmarshal([]byte(modelMapping), &modelMap)
		if err != nil {
			return errorWrapper(err, "unmarshal_model_mapping_failed", http.StatusInternalServerError)
		}
		if modelMap[textRequest.Model] != "" {
			textRequest.Model = modelMap[textRequest.Model]
			isModelMapped = true
		}
	}
	apiType := APITypeOpenAI
	switch channelType {
	case common.ChannelTypeAnthropic:
		apiType = APITypeClaude
	case common.ChannelTypeBaidu:
		apiType = APITypeBaidu
	case common.ChannelTypePaLM:
		apiType = APITypePaLM
	case common.ChannelTypeZhipu:
		apiType = APITypeZhipu
	case common.ChannelTypeAli:
		apiType = APITypeAli
	case common.ChannelTypeXunfei:
		apiType = APITypeXunfei
	case common.ChannelTypeAIProxyLibrary:
		apiType = APITypeAIProxyLibrary
	}
	baseURL := common.ChannelBaseURLs[channelType]
	requestURL := c.Request.URL.String()
	if c.GetString("base_url") != "" {
		baseURL = c.GetString("base_url")
	}
	fullRequestURL := fmt.Sprintf("%s%s", baseURL, requestURL)
	switch apiType {
	case APITypeOpenAI:
		if channelType == common.ChannelTypeAzure {
			// https://learn.microsoft.com/en-us/azure/cognitive-services/openai/chatgpt-quickstart?pivots=rest-api&tabs=command-line#rest-api
			query := c.Request.URL.Query()
			apiVersion := query.Get("api-version")
			if apiVersion == "" {
				apiVersion = c.GetString("api_version")
			}
			requestURL := strings.Split(requestURL, "?")[0]
			requestURL = fmt.Sprintf("%s?api-version=%s", requestURL, apiVersion)
			baseURL = c.GetString("base_url")
			task := strings.TrimPrefix(requestURL, "/v1/")
			model_ := textRequest.Model
			model_ = strings.Replace(model_, ".", "", -1)
			// https://github.com/songquanpeng/one-api/issues/67
			model_ = strings.TrimSuffix(model_, "-0301")
			model_ = strings.TrimSuffix(model_, "-0314")
			model_ = strings.TrimSuffix(model_, "-0613")
			fullRequestURL = fmt.Sprintf("%s/openai/deployments/%s/%s", baseURL, model_, task)
		}
	case APITypeClaude:
		fullRequestURL = "https://api.anthropic.com/v1/complete"
		if baseURL != "" {
			fullRequestURL = fmt.Sprintf("%s/v1/complete", baseURL)
		}
	case APITypeBaidu:
		switch textRequest.Model {
		case "ERNIE-Bot":
			fullRequestURL = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions"
		case "ERNIE-Bot-turbo":
			fullRequestURL = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/eb-instant"
		case "BLOOMZ-7B":
			fullRequestURL = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/bloomz_7b1"
		case "Embedding-V1":
			fullRequestURL = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/embeddings/embedding-v1"
		}
		apiKey := c.Request.Header.Get("Authorization")
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
		var err error
		if apiKey, err = getBaiduAccessToken(apiKey); err != nil {
			return errorWrapper(err, "invalid_baidu_config", http.StatusInternalServerError)
		}
		fullRequestURL += "?access_token=" + apiKey
	case APITypePaLM:
		fullRequestURL = "https://generativelanguage.googleapis.com/v1beta2/models/chat-bison-001:generateMessage"
		if baseURL != "" {
			fullRequestURL = fmt.Sprintf("%s/v1beta2/models/chat-bison-001:generateMessage", baseURL)
		}
		apiKey := c.Request.Header.Get("Authorization")
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
		fullRequestURL += "?key=" + apiKey
	case APITypeZhipu:
		method := "invoke"
		if textRequest.Stream {
			method = "sse-invoke"
		}
		fullRequestURL = fmt.Sprintf("https://open.bigmodel.cn/api/paas/v3/model-api/%s/%s", textRequest.Model, method)
	case APITypeAli:
		fullRequestURL = "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
		if relayMode == RelayModeEmbeddings {
			fullRequestURL = "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding"
		}
	case APITypeAIProxyLibrary:
		fullRequestURL = fmt.Sprintf("%s/api/library/ask", baseURL)
	}
	var promptTokens int
	var completionTokens int
	switch relayMode {
	case RelayModeChatCompletions:
		promptTokens = countTokenMessages(textRequest.Messages, textRequest.Model)
	case RelayModeCompletions:
		promptTokens = countTokenInput(textRequest.Prompt, textRequest.Model)
	case RelayModeModerations:
		promptTokens = countTokenInput(textRequest.Input, textRequest.Model)
	}
	preConsumedTokens := common.PreConsumedQuota
	if textRequest.MaxTokens != 0 {
		preConsumedTokens = promptTokens + textRequest.MaxTokens
	}
	modelRatio := common.GetModelRatio(textRequest.Model)
	groupRatio := common.GetGroupRatio(group)
	ratio := modelRatio * groupRatio
	preConsumedQuota := int(float64(preConsumedTokens) * ratio)
	userQuota, err := model.CacheGetUserQuota(userId)
	if err != nil {
		return errorWrapper(err, "get_user_quota_failed", http.StatusInternalServerError)
	}
	err = model.CacheDecreaseUserQuota(userId, preConsumedQuota)
	if err != nil {
		return errorWrapper(err, "decrease_user_quota_failed", http.StatusInternalServerError)
	}
	if userQuota > 100*preConsumedQuota {
		// in this case, we do not pre-consume quota
		// because the user has enough quota
		preConsumedQuota = 0
	}
	if consumeQuota && preConsumedQuota > 0 {
		err := model.PreConsumeTokenQuota(tokenId, preConsumedQuota)
		if err != nil {
			return errorWrapper(err, "pre_consume_token_quota_failed", http.StatusForbidden)
		}
	}
	var requestBody io.Reader
	if isModelMapped {
		jsonStr, err := json.Marshal(textRequest)
		if err != nil {
			return errorWrapper(err, "marshal_text_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonStr)
	} else {
		requestBody = c.Request.Body
	}
	switch apiType {
	case APITypeClaude:
		claudeRequest := requestOpenAI2Claude(textRequest)
		jsonStr, err := json.Marshal(claudeRequest)
		if err != nil {
			return errorWrapper(err, "marshal_text_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonStr)
	case APITypeBaidu:
		var jsonData []byte
		var err error
		switch relayMode {
		case RelayModeEmbeddings:
			baiduEmbeddingRequest := embeddingRequestOpenAI2Baidu(textRequest)
			jsonData, err = json.Marshal(baiduEmbeddingRequest)
		default:
			baiduRequest := requestOpenAI2Baidu(textRequest)
			jsonData, err = json.Marshal(baiduRequest)
		}
		if err != nil {
			return errorWrapper(err, "marshal_text_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonData)
	case APITypePaLM:
		palmRequest := requestOpenAI2PaLM(textRequest)
		jsonStr, err := json.Marshal(palmRequest)
		if err != nil {
			return errorWrapper(err, "marshal_text_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonStr)
	case APITypeZhipu:
		zhipuRequest := requestOpenAI2Zhipu(textRequest)
		jsonStr, err := json.Marshal(zhipuRequest)
		if err != nil {
			return errorWrapper(err, "marshal_text_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonStr)
	case APITypeAli:
		var jsonStr []byte
		var err error
		switch relayMode {
		case RelayModeEmbeddings:
			aliEmbeddingRequest := embeddingRequestOpenAI2Ali(textRequest)
			jsonStr, err = json.Marshal(aliEmbeddingRequest)
		default:
			aliRequest := requestOpenAI2Ali(textRequest)
			jsonStr, err = json.Marshal(aliRequest)
		}
		if err != nil {
			return errorWrapper(err, "marshal_text_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonStr)
	case APITypeAIProxyLibrary:
		aiProxyLibraryRequest := requestOpenAI2AIProxyLibrary(textRequest)
		aiProxyLibraryRequest.LibraryId = c.GetString("library_id")
		jsonStr, err := json.Marshal(aiProxyLibraryRequest)
		if err != nil {
			return errorWrapper(err, "marshal_text_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonStr)
	}

	var req *http.Request
	var resp *http.Response
	isStream := textRequest.Stream

	if apiType != APITypeXunfei { // cause xunfei use websocket
		req, err = http.NewRequest(c.Request.Method, fullRequestURL, requestBody)
		if err != nil {
			return errorWrapper(err, "new_request_failed", http.StatusInternalServerError)
		}
		apiKey := c.Request.Header.Get("Authorization")
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
		switch apiType {
		case APITypeOpenAI:
			if channelType == common.ChannelTypeAzure {
				req.Header.Set("api-key", apiKey)
			} else {
				req.Header.Set("Authorization", c.Request.Header.Get("Authorization"))
				if channelType == common.ChannelTypeOpenRouter {
					req.Header.Set("HTTP-Referer", "https://github.com/songquanpeng/one-api")
					req.Header.Set("X-Title", "One API")
				}
			}
		case APITypeClaude:
			req.Header.Set("x-api-key", apiKey)
			anthropicVersion := c.Request.Header.Get("anthropic-version")
			if anthropicVersion == "" {
				anthropicVersion = "2023-06-01"
			}
			req.Header.Set("anthropic-version", anthropicVersion)
		case APITypeZhipu:
			token := getZhipuToken(apiKey)
			req.Header.Set("Authorization", token)
		case APITypeAli:
			req.Header.Set("Authorization", "Bearer "+apiKey)
			if textRequest.Stream {
				req.Header.Set("X-DashScope-SSE", "enable")
			}
		default:
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
		req.Header.Set("Content-Type", c.Request.Header.Get("Content-Type"))
		req.Header.Set("Accept", c.Request.Header.Get("Accept"))
		//req.Header.Set("Connection", c.Request.Header.Get("Connection"))
		resp, err = httpClient.Do(req)
		if err != nil {
			return errorWrapper(err, "do_request_failed", http.StatusInternalServerError)
		}
		err = req.Body.Close()
		if err != nil {
			return errorWrapper(err, "close_request_body_failed", http.StatusInternalServerError)
		}
		err = c.Request.Body.Close()
		if err != nil {
			return errorWrapper(err, "close_request_body_failed", http.StatusInternalServerError)
		}
		isStream = isStream || strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")

		if resp.StatusCode != http.StatusOK {
			return relayErrorHandler(resp)
		}
	}

	var textResponse TextResponse
	tokenName := c.GetString("token_name")
	channelId := c.GetInt("channel_id")

	defer func() {
		// c.Writer.Flush()
		go func() {
			if consumeQuota {
				quota := 0
				completionRatio := common.GetCompletionRatio(textRequest.Model)
				promptTokens = textResponse.Usage.PromptTokens
				completionTokens = textResponse.Usage.CompletionTokens

				quota = promptTokens + int(float64(completionTokens)*completionRatio)
				quota = int(float64(quota) * ratio)
				if ratio != 0 && quota <= 0 {
					quota = 1
				}
				totalTokens := promptTokens + completionTokens
				if totalTokens == 0 {
					// in this case, must be some error happened
					// we cannot just return, because we may have to return the pre-consumed quota
					quota = 0
				}
				quotaDelta := quota - preConsumedQuota
				err := model.PostConsumeTokenQuota(tokenId, quotaDelta)
				if err != nil {
					common.SysError("error consuming token remain quota: " + err.Error())
				}
				err = model.CacheUpdateUserQuota(userId)
				if err != nil {
					common.SysError("error update user quota cache: " + err.Error())
				}
				if quota != 0 {
					logContent := fmt.Sprintf("模型倍率 %.2f，分组倍率 %.2f", modelRatio, groupRatio)
					model.RecordConsumeLog(userId, promptTokens, completionTokens, textRequest.Model, tokenName, quota, logContent)
					model.UpdateUserUsedQuotaAndRequestCount(userId, quota)
					model.UpdateChannelUsedQuota(channelId, quota)
				}
			}
		}()
	}()
	switch apiType {
	case APITypeOpenAI:
		if isStream {
			err, responseText := openaiStreamHandler(c, resp, relayMode)
			if err != nil {
				return err
			}
			textResponse.Usage.PromptTokens = promptTokens
			textResponse.Usage.CompletionTokens = countTokenText(responseText, textRequest.Model)

			// added by shy
			textResponse.Usage.TotalTokens = textResponse.Usage.PromptTokens + textResponse.Usage.CompletionTokens

			// added by shy
			// 遍历textRequest.Messages，存下用户的消息为json格式
			var messageStored MessageStored
			messageStored.Model = textRequest.Model
			messageStored.Messages = textRequest.Messages
			responseMessage := Message{
				Role: "assistant",
				Content: responseText,
			}
			messageStored.Time = time.Now().Format("2006-01-02 15:04:05")
			messageStored.Messages = append(messageStored.Messages, responseMessage)
			messageStored.Group = c.GetString("group")
			messageStored.UserId = c.GetInt("id")
			messageStored.TokenID = c.GetInt("token_id")
			messageStored.ChannelType = c.GetInt("channel")
			messageStored.Choices = textResponse.Choices
			messageStored.Usage = textResponse.Usage
			messageStored.Error = textResponse.Error
			// 保存到文件
			fileName := fmt.Sprintf("./messages/%d.json", messageStored.UserId)
			jsonStrStored, errRequest := json.Marshal(messageStored)
			jsonStrStored = append(jsonStrStored, []byte("\n")...)
			if errRequest != nil {
				return errorWrapper(errRequest, "marshal_text_request_failed", http.StatusInternalServerError)
			} else {
				f, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					return errorWrapper(err, "open_file_failed", http.StatusInternalServerError)
				}
				// 在文件末尾增加一行json
				if _, err := f.Write(jsonStrStored); err != nil {
					return errorWrapper(err, "write_file_failed", http.StatusInternalServerError)
				}
				if err := f.Close(); err != nil {
					return errorWrapper(err, "close_file_failed", http.StatusInternalServerError)
				}
				// 打印日志
				fmt.Sprintf("用户%d的消息已保存到文件%s", messageStored.UserId, fileName)
			}

			return nil
		} else {
			err, usage := openaiHandler(c, resp, consumeQuota, promptTokens, textRequest.Model)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		}
	case APITypeClaude:
		if isStream {
			err, responseText := claudeStreamHandler(c, resp)
			if err != nil {
				return err
			}
			textResponse.Usage.PromptTokens = promptTokens
			textResponse.Usage.CompletionTokens = countTokenText(responseText, textRequest.Model)
			return nil
		} else {
			err, usage := claudeHandler(c, resp, promptTokens, textRequest.Model)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		}
	case APITypeBaidu:
		if isStream {
			err, usage := baiduStreamHandler(c, resp)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		} else {
			var err *OpenAIErrorWithStatusCode
			var usage *Usage
			switch relayMode {
			case RelayModeEmbeddings:
				err, usage = baiduEmbeddingHandler(c, resp)
			default:
				err, usage = baiduHandler(c, resp)
			}
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		}
	case APITypePaLM:
		if textRequest.Stream { // PaLM2 API does not support stream
			err, responseText := palmStreamHandler(c, resp)
			if err != nil {
				return err
			}
			textResponse.Usage.PromptTokens = promptTokens
			textResponse.Usage.CompletionTokens = countTokenText(responseText, textRequest.Model)
			return nil
		} else {
			err, usage := palmHandler(c, resp, promptTokens, textRequest.Model)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		}
	case APITypeZhipu:
		if isStream {
			err, usage := zhipuStreamHandler(c, resp)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			// zhipu's API does not return prompt tokens & completion tokens
			textResponse.Usage.PromptTokens = textResponse.Usage.TotalTokens
			return nil
		} else {
			err, usage := zhipuHandler(c, resp)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			// zhipu's API does not return prompt tokens & completion tokens
			textResponse.Usage.PromptTokens = textResponse.Usage.TotalTokens
			return nil
		}
	case APITypeAli:
		if isStream {
			err, usage := aliStreamHandler(c, resp)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		} else {
			var err *OpenAIErrorWithStatusCode
			var usage *Usage
			switch relayMode {
			case RelayModeEmbeddings:
				err, usage = aliEmbeddingHandler(c, resp)
			default:
				err, usage = aliHandler(c, resp)
			}
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		}
	case APITypeXunfei:
		if isStream {
			auth := c.Request.Header.Get("Authorization")
			auth = strings.TrimPrefix(auth, "Bearer ")
			splits := strings.Split(auth, "|")
			if len(splits) != 3 {
				return errorWrapper(errors.New("invalid auth"), "invalid_auth", http.StatusBadRequest)
			}
			err, usage := xunfeiStreamHandler(c, textRequest, splits[0], splits[1], splits[2])
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		} else {
			return errorWrapper(errors.New("xunfei api does not support non-stream mode"), "invalid_api_type", http.StatusBadRequest)
		}
	case APITypeAIProxyLibrary:
		if isStream {
			err, usage := aiProxyLibraryStreamHandler(c, resp)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		} else {
			err, usage := aiProxyLibraryHandler(c, resp)
			if err != nil {
				return err
			}
			if usage != nil {
				textResponse.Usage = *usage
			}
			return nil
		}
	default:
		return errorWrapper(errors.New("unknown api type"), "unknown_api_type", http.StatusInternalServerError)
	}
}
