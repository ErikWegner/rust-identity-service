use super::Redis;

#[test]
fn write_value() {
    // Arrange
    let redis = Redis::new();
    let groups: Vec<String> = vec!["a".to_string(), "/b/".to_string()];
    let subject = "87f1e539-0d6e-41e9-971e-58f54565918a";

    // Act
    tokio_test::block_on(redis.set_cache_result(subject, &groups));

    // Assert: no exception here
}

#[test]
fn write_and_read_value() {
    // Arrange
    let redis = Redis::new();
    let groups: Vec<String> = vec!["a".to_string(), "/b/".to_string()];
    let subject = "87f1e539-0d6e-41e9-971e-58f54565918a";
    tokio_test::block_on(redis.set_cache_result(subject, &groups));

    // Act
    let result = tokio_test::block_on(redis.get_cache_result(subject));

    // Assert
    assert_eq!(groups, result.unwrap());
}
