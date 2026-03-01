import { motion } from 'framer-motion';
import { Settings, Zap, Shield, Sliders, ToggleLeft, ToggleRight, AlertTriangle } from 'lucide-react';
import { useSecurity } from '@/store/securityStore';
import { useState } from 'react';

const AdminPanel = () => {
  const {
    autonomousMode, setAutonomousMode, riskThreshold, setRiskThreshold,
    systemRiskScore, isAttackSimulated, simulateAttack, resetSimulation, isSimulating
  } = useSecurity();

  const [sensitivity, setSensitivity] = useState(75);
  const [learningRate, setLearningRate] = useState(0.3);
  const [geoBlocking, setGeoBlocking] = useState(true);
  const [deviceTrust, setDeviceTrust] = useState(true);
  const [mlModel, setMlModel] = useState<'isolation-forest' | 'lstm'>('isolation-forest');

  return (
    <div className="p-4 lg:p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold">Admin Panel</h1>
        <p className="text-xs text-muted-foreground font-mono mt-0.5">
          TrustNet AI configuration · Autonomous response settings
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Autonomous Mode */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="cyber-card rounded-xl p-5"
          style={{
            borderColor: autonomousMode ? 'hsl(185 100% 45% / 0.3)' : undefined,
          }}
        >
          <div className="flex items-center gap-2 mb-5">
            <Zap className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Digital Immune System</span>
          </div>

          <div className="space-y-4">
            {/* Autonomous toggle */}
            <div className="flex items-center justify-between p-3 rounded-lg border border-border">
              <div>
                <div className="text-sm font-medium">Autonomous Mode</div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  AI auto-responds to threats without human approval
                </div>
              </div>
              <button onClick={() => setAutonomousMode(!autonomousMode)} className="flex-shrink-0">
                {autonomousMode ? (
                  <ToggleRight className="w-8 h-8 text-primary" />
                ) : (
                  <ToggleLeft className="w-8 h-8 text-muted-foreground" />
                )}
              </button>
            </div>

            {/* Geo blocking */}
            <div className="flex items-center justify-between p-3 rounded-lg border border-border">
              <div>
                <div className="text-sm font-medium">Geo-Location Blocking</div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  Block logins from unauthorized countries
                </div>
              </div>
              <button onClick={() => setGeoBlocking(!geoBlocking)} className="flex-shrink-0">
                {geoBlocking ? (
                  <ToggleRight className="w-8 h-8 text-primary" />
                ) : (
                  <ToggleLeft className="w-8 h-8 text-muted-foreground" />
                )}
              </button>
            </div>

            {/* Device trust */}
            <div className="flex items-center justify-between p-3 rounded-lg border border-border">
              <div>
                <div className="text-sm font-medium">Device Fingerprint Trust</div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  Flag logins from unrecognized devices
                </div>
              </div>
              <button onClick={() => setDeviceTrust(!deviceTrust)} className="flex-shrink-0">
                {deviceTrust ? (
                  <ToggleRight className="w-8 h-8 text-primary" />
                ) : (
                  <ToggleLeft className="w-8 h-8 text-muted-foreground" />
                )}
              </button>
            </div>
          </div>
        </motion.div>

        {/* Risk thresholds */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="cyber-card rounded-xl p-5"
        >
          <div className="flex items-center gap-2 mb-5">
            <Sliders className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Risk Thresholds</span>
          </div>

          <div className="space-y-5">
            {/* Auto-block threshold */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-medium">Auto-Block Threshold</div>
                <div className="font-mono text-sm font-bold text-destructive">{riskThreshold}</div>
              </div>
              <input
                type="range"
                min={50}
                max={95}
                value={riskThreshold}
                onChange={(e) => setRiskThreshold(Number(e.target.value))}
                className="w-full h-1.5 rounded-full appearance-none cursor-pointer"
                style={{
                  background: `linear-gradient(to right, hsl(0 90% 55%) ${((riskThreshold - 50) / 45) * 100}%, hsl(220 25% 20%) ${((riskThreshold - 50) / 45) * 100}%)`
                }}
              />
              <div className="flex justify-between text-[9px] font-mono text-muted-foreground mt-1">
                <span>50 (Sensitive)</span>
                <span>95 (Permissive)</span>
              </div>
            </div>

            {/* Sensitivity */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-medium">Detection Sensitivity</div>
                <div className="font-mono text-sm font-bold text-warning">{sensitivity}%</div>
              </div>
              <input
                type="range"
                min={20}
                max={100}
                value={sensitivity}
                onChange={(e) => setSensitivity(Number(e.target.value))}
                className="w-full h-1.5 rounded-full appearance-none cursor-pointer"
                style={{
                  background: `linear-gradient(to right, hsl(38 95% 55%) ${sensitivity}%, hsl(220 25% 20%) ${sensitivity}%)`
                }}
              />
              <div className="flex justify-between text-[9px] font-mono text-muted-foreground mt-1">
                <span>20% (Low FP)</span>
                <span>100% (Max)</span>
              </div>
            </div>

            {/* Learning rate */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-medium">AI Learning Rate</div>
                <div className="font-mono text-sm font-bold text-primary">{learningRate.toFixed(2)}</div>
              </div>
              <input
                type="range"
                min={0.05}
                max={0.8}
                step={0.05}
                value={learningRate}
                onChange={(e) => setLearningRate(Number(e.target.value))}
                className="w-full h-1.5 rounded-full appearance-none cursor-pointer"
                style={{
                  background: `linear-gradient(to right, hsl(185 100% 45%) ${(learningRate / 0.8) * 100}%, hsl(220 25% 20%) ${(learningRate / 0.8) * 100}%)`
                }}
              />
            </div>

            {/* Response level legend */}
            <div className="p-3 rounded-lg border border-border text-[10px] font-mono space-y-1.5">
              <div className="text-muted-foreground font-medium mb-2">AUTO-RESPONSE LEVELS:</div>
              {[
                { range: '0–30', action: 'Normal monitoring', color: 'hsl(185 100% 45%)' },
                { range: '31–60', action: 'Warning + MFA challenge', color: 'hsl(38 95% 55%)' },
                { range: '61–85', action: 'Temporary session restriction', color: 'hsl(20 95% 55%)' },
                { range: '86–100', action: 'Auto-block + alert security team', color: 'hsl(0 90% 55%)' },
              ].map((level) => (
                <div key={level.range} className="flex items-center gap-2">
                  <span className="w-14" style={{ color: level.color }}>{level.range}</span>
                  <span className="text-muted-foreground">→</span>
                  <span style={{ color: level.color }}>{level.action}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* ML Model selection */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="cyber-card rounded-xl p-5"
        >
          <div className="flex items-center gap-2 mb-5">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Detection Engine</span>
          </div>

          <div className="space-y-3">
            {[
              {
                id: 'isolation-forest' as const,
                name: 'Isolation Forest',
                desc: 'Fast, real-time anomaly detection. Best for structured data patterns.',
                badge: 'ACTIVE',
              },
              {
                id: 'lstm' as const,
                name: 'LSTM Autoencoder',
                desc: 'Deep learning sequence analysis. Best for temporal behavioral patterns.',
                badge: 'AVAILABLE',
              },
            ].map((model) => (
              <button
                key={model.id}
                onClick={() => setMlModel(model.id)}
                className="w-full text-left p-4 rounded-lg border transition-all duration-200"
                style={{
                  background: mlModel === model.id ? 'hsl(185 100% 45% / 0.08)' : 'hsl(220 30% 8%)',
                  borderColor: mlModel === model.id ? 'hsl(185 100% 45% / 0.5)' : 'hsl(220 25% 15%)',
                }}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="text-sm font-medium" style={{ color: mlModel === model.id ? 'hsl(185 100% 45%)' : undefined }}>
                    {model.name}
                  </div>
                  <div
                    className="text-[9px] font-mono px-2 py-0.5 rounded"
                    style={{
                      background: mlModel === model.id ? 'hsl(185 100% 45% / 0.2)' : 'hsl(220 25% 15%)',
                      color: mlModel === model.id ? 'hsl(185 100% 45%)' : 'hsl(215 20% 50%)',
                    }}
                  >
                    {model.badge}
                  </div>
                </div>
                <div className="text-[10px] text-muted-foreground">{model.desc}</div>
              </button>
            ))}
          </div>
        </motion.div>

        {/* Manual override + simulate */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="cyber-card rounded-xl p-5"
        >
          <div className="flex items-center gap-2 mb-5">
            <Settings className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Manual Controls</span>
          </div>

          <div className="space-y-3">
            {/* System status */}
            <div className="p-3 rounded-lg border border-border">
              <div className="text-[10px] font-mono text-muted-foreground mb-2">SYSTEM STATUS</div>
              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Risk Score:</span>
                  <span style={{ color: systemRiskScore > 70 ? 'hsl(0 90% 55%)' : 'hsl(185 100% 45%)' }}>{systemRiskScore}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Mode:</span>
                  <span className="text-primary">{autonomousMode ? 'AUTO' : 'MANUAL'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Model:</span>
                  <span className="text-primary">{mlModel === 'isolation-forest' ? 'ISO-FOREST' : 'LSTM'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Threshold:</span>
                  <span className="text-warning">{riskThreshold}</span>
                </div>
              </div>
            </div>

            {/* Simulate button */}
            <motion.button
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              onClick={isAttackSimulated ? resetSimulation : simulateAttack}
              disabled={isSimulating}
              className="w-full py-3 rounded-lg font-mono text-sm font-bold transition-all flex items-center justify-center gap-2 disabled:opacity-60"
              style={isAttackSimulated ? {
                background: 'hsl(185 100% 45% / 0.1)',
                border: '1px solid hsl(185 100% 45% / 0.4)',
                color: 'hsl(185 100% 45%)',
              } : {
                background: 'hsl(0 90% 55% / 0.15)',
                border: '1px solid hsl(0 90% 55% / 0.5)',
                color: 'hsl(0 90% 55%)',
                boxShadow: '0 0 30px hsl(0 90% 55% / 0.25)',
              }}
            >
              <AlertTriangle className="w-4 h-4" />
              {isSimulating ? 'SIMULATING ATTACK...' : isAttackSimulated ? 'RESET — CLEAR INCIDENT' : 'SIMULATE COMPROMISED LOGIN'}
            </motion.button>

            <button
              className="w-full py-2.5 rounded-lg font-mono text-xs font-medium border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 transition-all"
            >
              EXPORT SECURITY REPORT
            </button>

            <button
              className="w-full py-2.5 rounded-lg font-mono text-xs font-medium border border-border text-muted-foreground hover:text-foreground hover:border-warning/30 transition-all"
            >
              RECALIBRATE AI BASELINE
            </button>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default AdminPanel;
