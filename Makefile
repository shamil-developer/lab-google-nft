mock:
	go run github.com/golang/mock/mockgen@v1.6.0 -source=internal/infrastructure/traffic_filter/provider.go -destination=internal/infrastructure/traffic_filter/mock_nft_conn_test.go -package=nftables_test -mock_names=NFTConn=MockNFTConn
