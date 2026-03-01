# TrustNet AI Guardian ML Backend

Advanced pre-trained machine learning models for security threat detection, anomaly detection, and risk analysis.

## Overview

This backend provides state-of-the-art ML models integrated with the TrustNet security system:

### **Models Included**

1. **Isolation Forest Anomaly Detection**
   - Detects unusual patterns in user behavior
   - Identifies insider threats and compromised accounts
   - Real-time anomaly scoring

2. **Risk Scoring Engine**
   - Weighted behavioral deviation analysis
   - Multi-dimensional threat assessment
   - Automatic risk level classification (Low/Medium/High/Critical)

3. **Network Propagation Analyzer**
   - Analyzes risk spread through network nodes
   - Identifies critical nodes vulnerable to compromise
   - Attack path detection

## Architecture

```
backend/
├── main.py                 # FastAPI application
├── requirements.txt        # Python dependencies
├── models/
│   ├── ml_models.py       # ML models (Isolation Forest, Risk Scorer, etc.)
│   └── __init__.py
└── routes/
    ├── schemas.py         # Pydantic schemas for API validation
    └── ml_routes.py       # API endpoints
```

## Installation

### Prerequisites
- Python 3.10+
- pip or conda

### Setup Steps

1. **Create virtual environment**
   ```bash
   cd backend
   python -m venv venv
   ```

2. **Activate virtual environment**
   - Windows: `.\venv\Scripts\activate`
   - Mac/Linux: `source venv/bin/activate`

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Running

### Start the Backend Server

```bash
cd backend
.\venv\Scripts\uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The server will start on `http://localhost:8000`

### API Documentation

Once running, visit:
- **Swagger UI**: `http://localhost:8000/docs`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

## API Endpoints

### Health Check
```
GET /api/health
```

### Calculate Risk Score
```
POST /api/risk-score
```
Calculates behavioral risk score for a user based on multiple metrics.

**Request:**
```json
{
  "user_id": "u1",
  "behavior_metrics": {
    "normal_login_time": 9.2,
    "actual_login_time": 19.5,
    "normal_session_duration": 4.5,
    "actual_session_duration": 0.3,
    "normal_data_volume": 120,
    "actual_data_volume": 850,
    "normal_api_calls": 45,
    "actual_api_calls": 312,
    "normal_geo_distance": 0,
    "actual_geo_distance": 9847
  },
  "anomaly_score": 0.85
}
```

### Detect Anomalies
```
POST /api/anomaly-detection
```
Detects anomalies in behavioral records using Isolation Forest.

**Request:**
```json
{
  "records": [
    {"session_duration": 4.2, "data_volume": 110, "api_calls": 48},
    {"session_duration": 0.3, "data_volume": 850, "api_calls": 312}
  ]
}
```

### Analyze Network Propagation
```
POST /api/propagation-analysis
```
Analyzes risk propagation through network topology.

**Request:**
```json
{
  "nodes": [
    {"id": "n1", "label": "Server A", "type": "server", "propagationRisk": 45, ...},
    {"id": "n2", "label": "User 1", "type": "user", "propagationRisk": 30, ...}
  ],
  "edges": [
    {"from": "n1", "to": "n2", "active": true, "attackPath": false}
  ]
}
```

### Batch Risk Analysis
```
POST /api/batch-risk-analysis
```
Analyzes multiple users in a single request.

## Machine Learning Details

### Isolation Forest
- **Algorithm**: Isolation Forest (scikit-learn)
- **Purpose**: Identify outliers/anomalies in behavioral data
- **Training**: Trained on synthetic normal behavior patterns
- **Output**: Anomaly score (0-1), where higher = more anomalous

### Risk Scoring
- **Weights Applied**:
  - Login time deviation: 15%
  - Session duration deviation: 12%
  - Data volume deviation: 20%
  - API calls deviation: 18%
  - Geographic distance deviation: 25%
  - Anomaly score: 10%

- **Risk Levels**:
  - Safe: 0-10
  - Low: 10-30
  - Medium: 30-50
  - High: 50-75
  - Critical: 75-100

### Network Propagation
- Calculates risk spread based on:
  - Node risk score
  - Neighbor influence
  - Active attack paths

## Frontend Integration

The React frontend communicates with the backend via:

1. **ML Backend Service** (`src/services/mlBackendService.ts`)
   - Handles all API calls to the backend
   - Includes error handling and retries

2. **useMLBackend Hook** (`src/hooks/useMLBackend.ts`)
   - React hook for backend integration
   - Auto-detects backend availability
   - Provides async ML operations

### Usage in Components

```typescript
import { useMLBackend } from '@/hooks/useMLBackend';

const MyComponent = () => {
  const { isConnected, calculateRisk } = useMLBackend();

  const analyzeUser = async (userId: string, metrics: any) => {
    const result = await calculateRisk(userId, metrics);
    console.log('Risk Score:', result?.overall_score);
  };

  return (
    <div>
      Backend: {isConnected ? '✓ Connected' : '⚠ Disconnected'}
    </div>
  );
};
```

## Performance

- **Anomaly Detection**: ~10-50ms per record
- **Risk Scoring**: ~5ms per user
- **Propagation Analysis**: ~100-500ms depending on network size
- **Batch Operations**: Optimized for handling 100+ records

## Production Considerations

### Model Training
For production, you should train models on actual data:

```python
from backend.models.ml_models import anomaly_detector
import numpy as np

# Your historical data
historical_data = np.array([...])  # (n_samples, n_features)
feature_names = ['feature1', 'feature2', ...]

result = anomaly_detector.train(historical_data, feature_names)
anomaly_detector.save('path/to/model.pkl')
```

### Security
- Enable HTTPS in production
- Restrict CORS origins
- Implement authentication
- Rate limit endpoints
- Use environment variables for configuration

### Scaling
- Use containerization (Docker)
- Deploy multiple backend instances
- Load balance with Nginx or similar
- Consider async job queues for batch operations

## Troubleshooting

### Backend not connecting
1. Ensure backend is running: `http://localhost:8000/docs`
2. Check frontend environment variable: `REACT_APP_ML_API_URL`
3. Verify CORS settings in `main.py`

### Memory issues with large datasets
- Reduce batch size
- Process data in chunks
- Use stream processing for real-time analysis

### Model accuracy concerns
- Retrain models with more data
- Tune contamination parameter in IsolationForest
- Add feature engineering pipeline

## Technologies

- **FastAPI**: Modern Python web framework
- **scikit-learn**: Machine learning library
- **NumPy/Pandas**: Data processing
- **Pydantic**: Data validation
- **Uvicorn**: ASGI server

## License

Same as TrustNet AI Guardian main project

## Support

For issues or questions, refer to the main TrustNet documentation.
