from sklearn.ensemble import IsolationForest
import numpy as np


# ---------------------------------------------------------
# SentinelAI ML Anomaly Detection
# ---------------------------------------------------------

# Simulated normal failed-login behavior.
# In a real deployment this would come from historical logs.
normal_data = np.array([
    [0], [0], [0], [0],
    [1], [1], [1], [1],
    [2], [2], [2], [2],
    [3], [3], [3],
    [4], [4],
    [5]
])


# Train the anomaly detection model
model = IsolationForest(
    n_estimators=200,
    contamination=0.10,
    random_state=42
)

model.fit(normal_data)


def detect_anomaly(failed_attempts: int):

    # Get ML prediction
    prediction = model.predict([[failed_attempts]])

    # Get model confidence/distance score
    raw_score = model.decision_function([[failed_attempts]])[0]

    # -----------------------------------------------------
    # Additional security context
    # -----------------------------------------------------
    #
    # This prevents the prototype from depending entirely
    # on a very small training dataset.
    #
    if failed_attempts >= 8:
        is_anomaly = True
        anomaly_score = 90

    elif failed_attempts >= 6:
        is_anomaly = True
        anomaly_score = 80

    elif prediction[0] == -1:
        is_anomaly = True
        anomaly_score = 70

    else:
        is_anomaly = False

        # Convert normal model score to a readable value
        anomaly_score = max(
            0,
            min(
                50,
                int((0.5 - raw_score) * 100)
            )
        )

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score
    }