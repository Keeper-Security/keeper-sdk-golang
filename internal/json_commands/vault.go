package json_commands

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
)

type RecordAddCommand struct {
	api.AuthorizedCommand
	RecordUid  string                 `json:"record_uid"`
	RecordType string                 `json:"record_type"`
	RecordKey  string                 `json:"record_key"`
	HowLongAgo float64                `json:"how_long_ago"`
	FolderType string                 `json:"folder_type"`
	FolderUid  string                 `json:"folder_uid"`
	FolderKey  string                 `json:"folder_key"`
	Data       string                 `json:"data"`
	Extra      string                 `json:"extra"`
	Udata      map[string]interface{} `json:"udata"`
}

func (c *RecordAddCommand) CommandName() string {
	return "record_add"
}

type RecordObject struct {
	RecordUid          string                 `json:"record_uid"`
	SharedFolderUid    string                 `json:"shared_folder_uid"`
	TeamUid            string                 `json:"team_uid"`
	Version            int32                  `json:"version"`
	Revision           int64                  `json:"revision"`
	RecordKey          string                 `json:"record_key"`
	ClientModifiedTime float64                `json:"client_modified_time"`
	Data               string                 `json:"data"`
	Extra              string                 `json:"extra"`
	Udata              map[string]interface{} `json:"udata,omitempty"`
	NonSharedData      string                 `json:"non_shared_data,omitempty"`
}

type RecordUpdateCommand struct {
	api.AuthorizedCommand
	DeviceId      string          `json:"device_id,omitempty"`
	Pt            string          `json:"pt,omitempty"`
	ClientTime    float64         `json:"client_time,omitempty"`
	AddRecords    []*RecordObject `json:"add_records,omitempty"`
	UpdateRecords []*RecordObject `json:"update_records,omitempty"`
	RemoveRecords []string        `json:"remove_records,omitempty"`
	DeleteRecords []string        `json:"delete_records,omitempty"`
}

func (c *RecordUpdateCommand) CommandName() string {
	return "record_update"
}

type StatusObject struct {
	RecordUid string `json:"record_uid,omitempty"`
	Status    string `json:"status,omitempty"`
}

type RecordUpdateResponse struct {
	api.KeeperApiResponse
	AddRecords    []*StatusObject `json:"add_records,omitempty"`
	UpdateRecords []*StatusObject `json:"update_records,omitempty"`
	RemoveRecords []*StatusObject `json:"remove_records,omitempty"`
	DeleteRecords []*StatusObject `json:"delete_records,omitempty"`
}

type PreDeleteObject struct {
	ObjectUid        string `json:"object_uid,omitempty"`
	ObjectType       string `json:"object_type,omitempty"`
	FromUid          string `json:"from_uid,omitempty"`
	FromType         string `json:"from_type,omitempty"`
	DeleteResolution string `json:"delete_resolution,omitempty"`
}
type PreDeleteCommand struct {
	api.KeeperApiResponse
	Objects []*PreDeleteObject `json:"objects,omitempty"`
}

type RequestUploadCommand struct {
	api.AuthorizedCommand
	FileCount      int `json:"file_count,omitempty"`
	ThumbnailCount int `json:"thumbnail_count,omitempty"`
}

func (c *RequestUploadCommand) CommandName() string {
	return "request_upload"
}

type UploadObject struct {
	MaxSize           float64                `json:"max_size"`
	Url               string                 `json:"url"`
	SuccessStatusCode int                    `json:"success_status_code"`
	FileId            string                 `json:"file_id"`
	FileParameter     string                 `json:"file_parameter"`
	Parameters        map[string]interface{} `json:"parameters"`
}
type RequestUploadResponse struct {
	api.KeeperApiResponse
	FileUploads      []*UploadObject `json:"file_uploads"`
	ThumbnailUploads []*UploadObject `json:"thumbnail_uploads"`
}

type RequestDownloadCommand struct {
	api.AuthorizedCommand
	RecordUid       string   `json:"record_uid,omitempty"`
	SharedFolderUid string   `json:"shared_folder_uid,omitempty"`
	TeamUid         string   `json:"team_uid,omitempty"`
	FileIds         []string `json:"file_ids,omitempty"`
}

func (c *RequestDownloadCommand) CommandName() string {
	return "request_download"
}

type DownloadObject struct {
	Url string `json:"url"`
}
type RequestDownloadResponse struct {
	api.KeeperApiResponse
	Downloads []*DownloadObject `json:"downloads"`
}
