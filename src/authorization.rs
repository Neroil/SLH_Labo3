//! Wrapper d'appel à Casbin pour la vérification statique
//! des conventions objet-action

use casbin::CoreApi;
use log::{error, info};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

use crate::models::{MedicalReport, Role, UserData};

const CONFIG: &str = "access_control/model.conf";
const POLICY: &str = "access_control/policy.csv";

/// Un enforcer Casbin
pub struct Enforcer(casbin::Enforcer);

type CasbinResult = Result<(), AccessDenied>;

/// Une erreur sans détails en cas d'accès refusé
#[derive(Debug, Error)]
#[error("Accès refusé.")]
pub struct AccessDenied;

/// Un contexte contenant une référence à un enforcer et à un sujet.
pub struct Context<'ctx> {
    enforcer: &'ctx Enforcer,
    subject: &'ctx UserData,
}

impl Enforcer {
    pub fn load() -> Result<Self, casbin::Error> {
        let mut enforcer = futures::executor::block_on(casbin::Enforcer::new(CONFIG, POLICY))?;
        futures::executor::block_on(enforcer.load_policy())?;
        Ok(Enforcer(enforcer))
    }

    pub fn with_subject<'ctx>(&'ctx self, subject: &'ctx UserData) -> Context<'ctx> {
        Context {
            enforcer: self,
            subject,
        }
    }
}

impl Context<'_> {
    fn enforce<O>(&self, object: O, action: &str) -> CasbinResult
    where
        O: Serialize + std::fmt::Debug + std::hash::Hash,
    {
        let subject = self.subject;

        info!(
            "Enforcing {}",
            json!({ "sub": subject, "obj": &object, "act": action })
        );
        match self.enforcer.0.enforce((subject, &object, action)) {
            Err(e) => {
                error!("Casbin error: {e:?}");
                Err(AccessDenied)
            }
            Ok(r) => {
                info!("Granted: {r}");
                if r {
                    Ok(())
                } else {
                    Err(AccessDenied)
                }
            }
        }
    }

    pub fn read_data(&self, patient: &UserData) -> CasbinResult {
        self.enforce(patient, "read-data")
    }

    pub fn update_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "update-data")
    }

    pub fn delete_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "delete-data")
    }

    pub fn add_report(&self, patient: &UserData, report: &MedicalReport) -> CasbinResult {
        self.enforce(
            json!({ "patient": patient, "report": report }),
            "add-report",
        )
    }

    pub fn read_report(&self, report: &MedicalReport, patient: &UserData) -> CasbinResult {
        self.enforce(json!({"report": report, "patient": patient}), "read-report")
    }

    pub fn update_report(&self, report: &MedicalReport) -> CasbinResult {
        self.enforce(report, "update-report")
    }

    pub fn update_role(&self, target: &UserData, role: Role) -> CasbinResult {
        self.enforce(json!({ "target": target, "role": role }), "update-role")
    }

    pub fn add_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "add-doctor")
    }

    pub fn remove_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "remove-doctor")
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::models::{BloodType, PersonalData, Role, UserData, UserID, MedicalReport, ReportID, MedicalFolder};
    use crate::utils::input_validation::{AVSNumber, Username};
    use crate::utils::password_utils::{hash, PWHash};

    fn create_test_user(id: UserID, username: &str, role: Role, has_folder: bool) -> UserData {
        let medical_folder = if has_folder {
            Some(MedicalFolder {
                personal_data: PersonalData {
                    avs_number: AVSNumber::try_from("756.1234.5678.97".to_string()).unwrap(),
                    blood_type: BloodType::A,
                },
                doctors: Default::default(),
            })
        } else {
            None
        };

        UserData {
            id,
            role,
            username: Username::new(username.to_string()),
            password: hash("dummy"),
            medical_folder,
        }
    }

    fn setup() -> (Enforcer, UserData, UserData, UserData) {
        let enforcer = Enforcer::load().unwrap();

        let admin = create_test_user(UserID::new(), "admin", Role::Admin, false);
        let patient = create_test_user(UserID::new(), "patient", Role::Patient, true);
        let doctor = create_test_user(UserID::new(), "doctor", Role::Doctor, false);

        (enforcer, admin, patient, doctor)
    }

    #[test]
    fn test_admin_permissions() {
        let (enforcer, admin, patient, _) = setup();
        let ctx = enforcer.with_subject(&admin);

        // Admin should be able to read any user's data
        assert!(ctx.read_data(&patient).is_ok());

        // Admin should be able to update roles
        assert!(ctx.update_role(&patient, Role::Doctor).is_ok());
    }

    #[test]
    fn test_patient_permissions() {
        let (enforcer, _, patient, doctor) = setup();
        let ctx = enforcer.with_subject(&patient);

        // Patient should be able to read their own data
        assert!(ctx.read_data(&patient).is_ok());

        // Patient should be able to update their own data
        assert!(ctx.update_data(&patient).is_ok());

        // Patient should be able to delete their own data
        assert!(ctx.delete_data(&patient).is_ok());

        // Patient should be able to add doctors
        assert!(ctx.add_doctor(&patient, &doctor).is_ok());

        // Patient should not be able to read other patient's data
        let other_patient = create_test_user(UserID::new(), "other", Role::Patient, true);
        assert!(ctx.read_data(&other_patient).is_err());
    }

    #[test]
    fn test_doctor_permissions() {
        let (enforcer, _, patient, doctor) = setup();
        let ctx = enforcer.with_subject(&doctor);

        // Create a test report
        let report = MedicalReport {
            id: ReportID::new(),
            title: "Test Report".to_string(),
            author: doctor.id,
            patient: patient.id,
            content: "Test content".to_string(),
        };

        // Doctor should be able to add reports
        assert!(ctx.add_report(&patient, &report).is_ok());

        // Doctor should be able to read their own reports
        assert!(ctx.read_report(&report, &patient).is_ok());

        // Doctor should be able to update their own reports
        assert!(ctx.update_report(&report).is_ok());
    }

    #[test]
    fn test_unauthorized_access() {
        let (enforcer, _, patient, _) = setup();
        let other_patient = create_test_user(UserID::new(), "other", Role::Patient, true);
        let ctx = enforcer.with_subject(&other_patient);

        // Other patient should not be able to read patient's data
        assert!(ctx.read_data(&patient).is_err());

        // Other patient should not be able to update patient's data
        assert!(ctx.update_data(&patient).is_err());

        // Other patient should not be able to delete patient's data
        assert!(ctx.delete_data(&patient).is_err());
    }

    #[test]
    fn test_doctor_patient_relationship() {
        let (enforcer, _, mut patient, doctor) = setup();

        // Add doctor to patient's medical folder
        if let Some(ref mut folder) = patient.medical_folder {
            folder.doctors.insert(doctor.id);
        }

        let ctx = enforcer.with_subject(&doctor);

        // Doctor should be able to read their patient's data
        assert!(ctx.read_data(&patient).is_ok());

        // Create a test report
        let report = MedicalReport {
            id: ReportID::new(),
            title: "Test Report".to_string(),
            author: doctor.id,
            patient: patient.id,
            content: "Test content".to_string(),
        };

        // Doctor should be able to read reports of their patients
        assert!(ctx.read_report(&report, &patient).is_ok());
    }
}
