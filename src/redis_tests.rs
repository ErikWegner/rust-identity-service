use crate::tests::get_redis;

#[tokio::test]
async fn write_value() {
    // Arrange
    let redis = get_redis();
    let groups: Vec<String> = vec!["a".to_string(), "/b/".to_string()];
    let subject = "87f1e539-0d6e-41e9-971e-58f54565918a";

    // Act
    redis.set_cache_result(subject, &groups).await;

    // Assert: no exception here
}

#[tokio::test]
async fn write_and_read_value() {
    // Arrange
    let redis = get_redis();
    let groups: Vec<String> = vec!["a".to_string(), "/b/".to_string()];
    let subject = "87f1e539-0d6e-41e9-971e-58f54565918a";
    redis.set_cache_result(subject, &groups).await;

    // Act
    let result = redis.get_cache_result(subject).await;

    // Assert
    assert_eq!(groups, result.unwrap());
}
