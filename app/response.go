package app

type Auth struct {
	Token      string `json:"token"`
	Expire_at  int64 `json:"expire_at"`
}

type AuthResponse struct {
  Success int `json:"success"`
  Message string `json:"message"`
  Data *Auth `json:"data"`
}