package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.model.Company;
import com.demo.userlogin.springsecuritylogin.model.Job;
import jakarta.annotation.PostConstruct;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/jobs")
public class JobController {

    private final List<Job> jobs = new ArrayList<>();

    @PostConstruct
    public void init() {
        jobs.add(new Job("Software Engineer", "Full-time", "Develop and maintain software applications", "New York, NY", "100000", new Company("TechCorp", "Innovative tech solutions", "contact@techcorp.com", "123-456-7890")));
        jobs.add(new Job("Data Scientist", "Full-time", "Analyze and interpret complex data", "San Francisco, CA", "120000", new Company("DataSolutions", "Data analytics and AI", "info@datasolutions.com", "123-456-7891")));
        jobs.add(new Job("DevOps Engineer", "Full-time", "Manage and automate infrastructure", "Austin, TX", "110000", new Company("CloudNet", "Cloud services and solutions", "support@cloudnet.com", "123-456-7892")));
        jobs.add(new Job("Front-end Developer", "Contract", "Design and develop user interfaces", "Remote", "90000", new Company("WebWorks", "Web development services", "jobs@webworks.com", "123-456-7893")));
        jobs.add(new Job("Project Manager", "Full-time", "Manage IT projects and teams", "Chicago, IL", "105000", new Company("ITPro", "IT consulting and solutions", "pm@itpro.com", "123-456-7894")));
        jobs.add(new Job("Cybersecurity Analyst", "Full-time", "Protect systems and networks", "Seattle, WA", "115000", new Company("SecureTech", "Cybersecurity services", "security@securetech.com", "123-456-7895")));
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping
    public List<Job> getAllJobs(@RequestParam(name = "_limit", required = false) Integer limit) {
        if (limit != null && limit > 0) {
            return jobs.stream().limit(limit).collect(Collectors.toList());
        }
        return jobs;
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/{id}")
    public Job getJobById(@PathVariable String id) {
        return jobs.stream()
                .filter(job -> job.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Job not found"));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public Job createJob(@RequestBody Job job) {
        jobs.add(job);
        return job;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public Job updateJob(@PathVariable String id, @RequestBody Job jobDetails) {
        Job job = jobs.stream()
                .filter(j -> j.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Job not found"));

        job.setTitle(jobDetails.getTitle());
        job.setType(jobDetails.getType());
        job.setDescription(jobDetails.getDescription());
        job.setLocation(jobDetails.getLocation());
        job.setSalary(jobDetails.getSalary());
        job.setCompany(jobDetails.getCompany());

        return job;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public String deleteJob(@PathVariable String id) {
        Job job = jobs.stream()
                .filter(j -> j.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Job not found"));

        jobs.remove(job);
        return "Job with id " + id + " has been deleted";
    }
}
