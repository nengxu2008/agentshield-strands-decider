# Submission: Agent Experience Hackathon (Strands Decider)

Submit before 23 October 2026, 11:59 p.m. PT on the hackathon page.

- Repository: https://github.com/nengxu2008/agentshield-strands-decider
- Video: https://youtu.be/tGztQFYy4Eg
- Article: <paste the AWS Builder Center link after publishing submission/article/>
- Tags: #strands-decider-2b #tool-selection
- Agent on AWS: arn:aws:bedrock-agentcore:us-east-1:253270662483:runtime/deciderkit_agent-QSkyjVEnov

## Done

- Public repository (Apache-2.0): https://github.com/nengxu2008/agentshield-strands-decider
- Demo video: submission/video/demo.mp4 (166 s, recorded against the deployed AgentCore Runtime; same file as submission/video/AgentShield.mp4)
- Article bundle: submission/article/ (fields.md for title, description and tags; body.md; cover.png; img/ figures)
- Deployment: Amazon Bedrock AgentCore Runtime, us-east-1, runtime arn:aws:bedrock-agentcore:us-east-1:253270662483:runtime/deciderkit_agent-QSkyjVEnov (Amazon Nova Pro on Amazon Bedrock plus the AWS User Group Madurai hosted Strands Decider 2B)
- Measured: submission/bench/results.md (decider vs Amazon Nova Pro, 15 held-out cases) and submission/bench/agentshield/results.md (6-arm routing benchmark, 16 held-out scenarios)

## Left for the participant

1. Make sure the YouTube video above is set to Public (not Unlisted or Private).
2. Publish the article on AWS Builder Center in your own words (fields.md + body.md + cover.png + img/), with exactly the two tags #strands-decider-2b and #tool-selection, then paste its link above.
3. Submit the three links (repository, video, article) on the hackathon page before 23 October 2026, 11:59 p.m. PT.
4. After judging, run ./kit destroy to remove the AgentCore deployment.

Built with the AWS User Group Madurai Strands Decider hackathon kit.
