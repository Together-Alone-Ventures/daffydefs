import { useState } from "react";

interface ProfileSetupProps {
  onSave: (input: {
    email: string;
    birthdate: string;
    gender: string;
    display_name: string;
  }) => Promise<void>;
  loading: boolean;
  error: string | null;
}

export default function ProfileSetup({ onSave, loading, error }: ProfileSetupProps) {
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [birthdate, setBirthdate] = useState("");
  const [gender, setGender] = useState("");

  const handleSubmit = async () => {
    await onSave({
      display_name: displayName,
      email,
      birthdate,
      gender,
    });
  };

  const isValid = displayName.length >= 2 && displayName.length <= 30;

  return (
    <div className="card">
      <h2>Set Up Your Profile</h2>
      <p className="muted">Your profile canister has been created. Fill in your details to get started.</p>

      <div className="form-group">
        <label>Display Name *</label>
        <input
          type="text"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="2–30 characters"
          maxLength={30}
          disabled={loading}
        />
      </div>

      <div className="form-group">
        <label>Email</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="your@email.com"
          disabled={loading}
        />
      </div>

      <div className="form-group">
        <label>Birthdate</label>
        <input
          type="date"
          value={birthdate}
          onChange={(e) => setBirthdate(e.target.value)}
          disabled={loading}
        />
      </div>

      <div className="form-group">
        <label>Gender</label>
        <select value={gender} onChange={(e) => setGender(e.target.value)} disabled={loading}>
          <option value="">Select...</option>
          <option value="M">Male</option>
          <option value="F">Female</option>
          <option value="NB">Non-binary</option>
          <option value="O">Other</option>
          <option value="P">Prefer not to say</option>
        </select>
      </div>

      {error && <p className="error">{error}</p>}

      <button
        className="button button-primary"
        onClick={handleSubmit}
        disabled={!isValid || loading}
      >
        {loading ? "Saving..." : "Save Profile"}
      </button>
    </div>
  );
}
