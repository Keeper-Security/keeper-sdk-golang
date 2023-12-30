package auth

import (
	"encoding/json"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"go.uber.org/zap"
	"golang.org/x/net/websocket"
	"io"
	"reflect"
)

type PushCallback = func(*NotificationEvent) bool

type IPushEndpoint interface {
	io.Closer
	IsClosed() bool
	RegisterCallback(PushCallback)
	RemoveCallback(PushCallback)
	RemoveAllCallback()
	Push(*NotificationEvent)
	SendToPushChannel([]byte, bool) error
}

type NotificationEvent struct {
	Command              string `json:"command"`
	Event                string `json:"event"`
	Message              string `json:"message"`
	Email                string `json:"email"`
	Username             string `json:"username"`
	Approved             bool   `json:"approved"`
	Sync                 bool   `json:"sync"`
	Passcode             string `json:"passcode"`
	DeviceName           string `json:"deviceName"`
	EncryptedLoginToken  string `json:"encryptedLoginToken"`
	EncryptedDeviceToken string `json:"encryptedDeviceToken"`
	IPAddress            string `json:"ipAddress"`
}

type PushEndpoint struct {
	isClosed  bool
	callbacks []PushCallback
}

func (p *PushEndpoint) IsClosed() bool {
	return p.isClosed
}

func (p *PushEndpoint) Close() error {
	p.isClosed = true
	p.callbacks = nil
	return nil
}

func (p *PushEndpoint) RegisterCallback(cb PushCallback) {
	for i, e := range p.callbacks {
		if e == nil {
			p.callbacks[i] = cb
			return
		}
	}
	p.callbacks = append(p.callbacks, cb)
}

func (p *PushEndpoint) RemoveCallback(cb PushCallback) {
	vcb := reflect.ValueOf(cb)
	for i, e := range p.callbacks {
		if reflect.ValueOf(e) == vcb {
			p.callbacks[i] = nil
		}
	}
}

func (p *PushEndpoint) RemoveAllCallback() {
	p.callbacks = nil
}

func (p *PushEndpoint) Push(event *NotificationEvent) {
	for i, e := range p.callbacks {
		if e != nil {
			if e(event) {
				p.callbacks[i] = nil
			}
		}
	}
}

func (p *PushEndpoint) SendToPushChannel(_ []byte, _ bool) error {
	return nil
}

type webSocketEndpoint struct {
	PushEndpoint
	conn          *websocket.Conn
	encryptionKey []byte
}

func (wse *webSocketEndpoint) IsClosed() bool {
	if wse.conn == nil {
		return true
	}
	return wse.PushEndpoint.IsClosed()
}

func (wse *webSocketEndpoint) SendToPushChannel(data []byte, encrypted bool) (err error) {
	if !wse.isClosed {
		if encrypted {
			if data, err = api.EncryptAesV2(data, wse.encryptionKey); err != nil {
				return
			}
		}
		_, err = wse.conn.Write(data)
	} else {
		err = api.NewKeeperError("Push endpoint is closed")
	}
	return
}

func (wse *webSocketEndpoint) Close() (err error) {
	if wse.conn != nil {
		return wse.conn.Close()
	}
	return wse.PushEndpoint.Close()
}

func (wse *webSocketEndpoint) readLoop() {
	var logger = api.GetLogger()
	buffer := make([]byte, 4*1024)
	for {
		if n, e := wse.conn.Read(buffer); e == nil {
			if n > 0 {
				var data []byte
				if data, e = api.DecryptAesV2(buffer[:n], wse.encryptionKey); e == nil {
					event := new(NotificationEvent)
					if e = json.Unmarshal(data, event); e == nil {
						go wse.Push(event)
					}
				} else {
					logger.Warn("Push Notification decrypt error", zap.Error(e))
				}
			}
		} else {
			logger.Warn("Push Notification disconnected with error", zap.Error(e))
			break
		}
	}
	wse.isClosed = true
	if wse.conn != nil {
		_ = wse.conn.Close()
		wse.conn = nil
	}
}
func NewWebSocketEndpoint(url string, key []byte) IPushEndpoint {
	endpoint := &webSocketEndpoint{
		PushEndpoint: PushEndpoint{
			isClosed: false,
		},
		conn:          nil,
		encryptionKey: key,
	}

	go func() {
		var logger = api.GetLogger()
		var err error
		if endpoint.conn, err = websocket.Dial(url, "", "http://localhost/"); err != nil {
			logger.Warn("Connect to push server error", zap.Error(err))
			_ = endpoint.Close()
			return
		}
		endpoint.readLoop()
	}()
	return endpoint
}
