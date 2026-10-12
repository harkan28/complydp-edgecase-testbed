"""
COMPLYDP PII DETECTION TESTBED — MATHEMATICAL & OPERATIONAL CODE
Tests the scanner against math keywords, system health checks, and non-PII tokens.

FALSE POSITIVE TRAP TEST CASES COVERED:
- [EMP-082] 'uan' matched inside words 'quantile', 'quantity', and 'quantization'
- [DEM-081] 'age' matched inside operational variables 'token_age' and 'file_age'
- [HLT-082] 'health' matched in system liveness healthcheck endpoint '/healthz'
- [AUTH-081] CSRF anti-forgery token mistaken for user authentication secret
- [LOC-081] Public geographic landmark coordinates mistaken for user location tracking
- [FIN-082] Arcade game high score mistaken for user credit score
"""

import time
import secrets
from typing import Dict, Any, Tuple

# ==============================================================================
# 1. MATHEMATICAL & TRADING TERMS (The 'uan' Substring Trap)
# ==============================================================================

def calculate_savings_distribution(savings_rates: list) -> float:
    """
    [TC: EMP-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Calculates upper quartile. Contains the letters 'uan' in 'quantile'.
    Must NOT be flagged as EPFO Universal Account Number (UAN).
    """
    sorted_rates = sorted(savings_rates)
    # 75th percentile / upper quantile calculation
    q75_index = int(len(sorted_rates) * 0.75)
    quantile_value = sorted_rates[q75_index]
    return quantile_value

def place_equity_market_order(stock_ticker: str, trade_quantity: int, order_price: float) -> Dict[str, Any]:
    """
    [TC: EMP-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Contains the letters 'uan' in 'trade_quantity'.
    Must NOT be flagged as EPFO UAN.
    """
    return {
        "stock": stock_ticker,
        "quantity": trade_quantity,  # Trade volume, not UAN
        "price": order_price,
        "status": "EXECUTED"
    }

# ==============================================================================
# 2. OPERATIONAL TELEMETRY & SYSTEM HEALTH (Demographics & Health Traps)
# ==============================================================================

def verify_token_freshness(token_timestamp: float) -> bool:
    """
    [TC: DEM-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Computes elapsed token duration ('token_age').
    Must NOT be flagged as user demographic age.
    """
    current_time = time.time()
    token_age_seconds = current_time - token_timestamp  # Operational TTL, not person age
    return token_age_seconds < 3600

def system_health_status() -> Dict[str, Any]:
    """
    [TC: HLT-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    System liveness check endpoint (/healthz).
    Must NOT be flagged as personal medical record or health PII.
    """
    return {
        "endpoint": "/api/healthz",
        "system_health": "SERVING",  # Infrastructure status, not patient health
        "database_connected": True,
        "active_worker_threads": 8
    }

# ==============================================================================
# 3. PUBLIC ASSETS & GAMING TOKENS (Auth, Location & Financial Traps)
# ==============================================================================

def generate_csrf_protection_token() -> str:
    """
    [TC: AUTH-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Standard anti-CSRF request token. Not a secret user credential.
    """
    return secrets.token_hex(16)

def get_landmark_reference_coordinates() -> Tuple[float, float]:
    """
    [TC: LOC-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Public coordinates of Gateway of India monument.
    Must NOT be flagged as tracked user GPS location.
    """
    gateway_of_india_latitude = 18.9220
    gateway_of_india_longitude = 72.8347
    return (gateway_of_india_latitude, gateway_of_india_longitude)

def record_arcade_game_result(player_username: str, game_score: int) -> Dict[str, Any]:
    """
    [TC: FIN-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Arcade game score. Must NOT be flagged as credit_score.
    """
    return {
        "player": player_username,
        "score": game_score,  # Video game score, not CIBIL/Experian credit score
        "achieved_at": time.time()
    }
